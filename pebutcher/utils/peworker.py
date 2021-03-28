import pefile
from pefile import PE
from random import shuffle, randint
from typing import List
from string import ascii_uppercase
from struct import pack
from pebutcher.utils.helpers import mixed_list_to_bytes


class PeWorker:
    """
    PeWorker - класс, расширяющий pefile.
    Добавляет функциональность по "умной" записи структур данных в pe файл, что сам модуль pefile не поддерживает.
    """

    def __init__(self, pe: str):
        self.pe = PE(pe)
        self.random_section_names = [b'.puk', b'.kek', b'.chicky', b'bombonya',
                                     b'.chunky', b'.junky', b'.funky', b'.punky', b'.spunky', b'.skunky', b'.monkey',
                                     b'.booboo', b'.booboomba', b'.yaah', b'.tutudu',
                                     b'.t3x7', b'.d474', b'.rDaT4', b'.r310c', b'.p4g3', b'.1337',
                                     b'.palace', b'.budha', b'.beeba', b'.bubba', b'.tsoy', b'.putin', b'.trump',
                                     b'.no', b'.yes', b'.r3v', b'.3r5',
                                     b'.domo', b'.arigato', b'.mister', b'.roboto',
                                     b'.i_have', b'.higher', b'.grando', b'.anakin']

    def randomise_section_names(self):
        shuffle(self.random_section_names)
        for section, name in zip(self.pe.sections, self.random_section_names):
            section.Name = name

    def randomize_nt_header_location(self, bytelist: List[str], insert_offset: int) -> bytes:
        """
        Вставляет данные в pe файл и обновляет оффсеты прочих структур.

        :param bytelist: Данные для вставки (рандомный набор байт)
        :param insert_offset: оффсет (адрес в файле), куда будут вставлены данные
        :return: возвращает измененный pe файл, как набор байт
        """
        max_size = self.pe.OPTIONAL_HEADER.FileAlignment
        # если что-то не так в этом коде, то можно просто крашнуться насмерть
        # далее смысла существовать нет
        if len(bytelist) > max_size:
            raise ValueError("len(bytelist) > max_size")

        # если что-то не так в этом коде, то можно просто крашнуться насмерть
        # далее смысла существовать нет
        if (len(bytelist) % 4) != 0:
            raise ValueError("len(bytelist) % 4 != 0")

        nop_str = ['\x90'] * (max_size - len(bytelist))

        file_data = list(self.pe.__data__)

        total_size_of_sect_hdrs = 0
        for section in self.pe.sections:
            total_size_of_sect_hdrs += list(section.__pack__()).__len__()

        # вставим нули за section headers для паддинга
        offset_after_sect_hdr = self.pe.sections[0].get_file_offset() + total_size_of_sect_hdrs
        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = nop_str

        # TODO принимать bytelist не как лист строк, а как bytes
        # вставляем байты до NT_HEADER'ов
        file_data.insert(insert_offset, bytelist)
        self.pe.DOS_HEADER.e_lfanew += len(bytelist)

        # Обновляем все  PointerToRawData в соответсвие с размером вставки
        for section in self.pe.sections:
            section.PointerToRawData += max_size

        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

        # тае же правим все оффсеты структур
        for structure in self.pe.__structures__:
            offset = structure.get_file_offset()
            if offset >= insert_offset:
                if offset >= offset_after_sect_hdr:
                    structure.set_file_offset(offset + max_size)
                else:
                    structure.set_file_offset(offset + len(bytelist))

            offset = structure.get_file_offset()
            struct_data = list(structure.__pack__())
            file_data[offset:offset + len(struct_data)] = struct_data

        # TODO убрать костыль, приводящий все данные к байтам
        new_file_data: bytes = mixed_list_to_bytes(file_data)
        return new_file_data

    def modify_sections(self, total_sections_num: int, update_size_of_image: bool) -> bytes:
        """
        Функция изменяет секции в pe файле, добавляя новые до числа равного total_sections_num.

        :param total_sections_num: общее количество секций после работы функции
        :param update_size_of_image: нужно ли обновить SizeOfImage
        :return: возвращает измененный pe файл, как набор байт
        """
        num_sect_to_add = total_sections_num - self.pe.FILE_HEADER.NumberOfSections
        if num_sect_to_add == 0:
            raise ValueError()

        self.pe.FILE_HEADER.NumberOfSections = total_sections_num

        # выбираем случайные имена для секций
        shuffle(self.random_section_names)
        sect_names = self.random_section_names[:num_sect_to_add]

        # сделаем размер всех секций равным self.OPTIONAL_HEADER.FileAlignment
        max_size = self.pe.OPTIONAL_HEADER.FileAlignment

        file_data = list(self.pe.__data__)

        total_size_of_existing_sect_hdrs = 0
        for section in self.pe.sections:
            total_size_of_existing_sect_hdrs += list(section.__pack__()).__len__()
        sect_hdr_size = self.pe.sections[0].sizeof()
        total_size_of_new_sect_hdrs = num_sect_to_add * sect_hdr_size

        # создаем временную секцию, подход будет использоваться далее
        # TODO выделить в отдельную функцию
        tmp_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__, pe=self.pe)
        tmp_section.__unpack__(b'\0' * sect_hdr_size)
        nop_str = ['\x90'] * (max_size - total_size_of_new_sect_hdrs)

        # вычисляем конечный виртуальный адрес последней секции
        end_va = self.pe.sections[len(self.pe.sections) - 1].VirtualAddress + self.pe.sections[
            len(self.pe.sections) - 1].Misc_VirtualSize
        # округляем до размера страницы
        if end_va % 1000:
            end_va += (0x1000 - end_va % 0x1000)

        # вставляем SectionHeaders после существующих
        offset_after_sect_hdr = self.pe.sections[0].get_file_offset() + total_size_of_existing_sect_hdrs
        tmp_section.set_file_offset(offset_after_sect_hdr)
        i = 0
        while i < num_sect_to_add:
            tmp_section.Name = sect_names[i]
            tmp_section.set_file_offset(offset_after_sect_hdr)
            tmp_section.SizeOfRawData = max_size
            tmp_section.VirtualAddress = end_va + i * 0x1000
            tmp_section.PointerToRawData = 0x400
            tmp_section.Misc_VirtualSize = 0x200
            tmp_section.Characteristics = 0x40000040
            file_data.insert(offset_after_sect_hdr, tmp_section.__pack__())

            offset_after_sect_hdr += sect_hdr_size
            i += 1

        # на самом деле загрузчик исполняемых файлов винды не обращает внимание на OPTIONAL_HEADER.SizeOfImage
        # так что его можно не обновлять, но я все равно обновлю для чистоты
        if update_size_of_image:
            self.pe.OPTIONAL_HEADER.SizeOfImage = (tmp_section.Misc_VirtualSize + tmp_section.VirtualAddress)
        self.pe.OPTIONAL_HEADER.SizeOfHeaders += total_size_of_new_sect_hdrs

        # вставляем nopы для паддинга
        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = nop_str

        # обновляем PointerToRawData в секциях
        for section in self.pe.sections:
            section.PointerToRawData += max_size

        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

        # аналогично правим стркутуры
        # TODO выделить в отдельный метод
        for structure in self.pe.__structures__:
            offset = structure.get_file_offset()
            if offset >= offset_after_sect_hdr:
                structure.set_file_offset(offset + max_size)

            offset = structure.get_file_offset()
            struct_data = list(structure.__pack__())
            file_data[offset:offset + len(struct_data)] = struct_data

        new_file_data: bytes = mixed_list_to_bytes(file_data)
        return new_file_data

    def create_delay_load_entries(self, random_dll_list: List[str], random_functions_list) -> bytes:
        """
        Функция добавляет в конец секций секцию, где располагает таблицу дескрипторов отложенной загрузки,
        delay load IAT, delay load INT и табличку имен dll.

        :param random_dll_list: случайные библиотеки в структуре
        :param random_functions_list: функциии в таблице
        :return: аналогично предыдущим методам
        """
        file_data = list(self.pe.__data__)
        self.pe.FILE_HEADER.NumberOfSections += 1
        num_delay_load_entries = len(random_dll_list)

        i = 0
        dl_idt = []
        # создаем структуры
        while i < num_delay_load_entries:
            d_import_desc = pefile.Structure(self.pe.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__)
            struct_size = pefile.Structure(self.pe.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof()
            d_import_desc.__unpack__("\0" * struct_size)
            d_import_desc.grAttrs = 1
            d_import_desc.pIAT = 0xAAAAAAAA
            d_import_desc.pINT = 0xBBBBBBBB
            d_import_desc.szName = 0xCCCCCCCC
            dl_idt.append(d_import_desc)
            i += 1
        # создаем на одну дополнительную запись т.к. список структур нультерминирован
        d_import_desc = pefile.Structure(self.pe.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__)
        struct_size = pefile.Structure(self.pe.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof()
        d_import_desc.__unpack__("\0" * struct_size)
        dl_idt.append(d_import_desc)

        total_delay_load_directory_table_size = struct_size * (num_delay_load_entries + 1)
        # обновляем размер
        total_delay_load_data_size_for_everything = total_delay_load_directory_table_size

        tmp_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__, pe=self.pe)
        sect_hdr_size = self.pe.sections[0].sizeof()
        tmp_section.__unpack__("\0" * sect_hdr_size)

        existing_last_section_end_va = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize

        if existing_last_section_end_va % 1000:
            existing_last_section_end_va += (0x1000 - existing_last_section_end_va % 0x1000)

        offset_after_dlidt = existing_last_section_end_va + total_delay_load_directory_table_size
        x = 0
        # многомерный имен библиотек
        dl_dll_names = []
        # массив RVA указателей на код для динамической загрузки, адреса не настоящие
        dl_iat = []
        # массив RVA указателей на структуры hint/name
        dl_int = []
        # сами имена и хинты
        dl_hint_names = []
        # аккумулятор листов выше
        master_byte_array = []
        while x < num_delay_load_entries:
            dl_idt[x].szName = offset_after_dlidt + len(master_byte_array)
            dl_dll_names += [[]]
            dl_dll_names[x] += list(random_dll_list[x])
            dl_dll_names[x] += ['\x00']
            master_byte_array += dl_dll_names[x]
            dl_idt[x].pIAT = offset_after_dlidt + len(master_byte_array)
            num_functions_per_dll = 10
            i = 0

            # заполняем iat т.е. он ни от чего не зависит
            dl_iat += [[]]
            while i < num_functions_per_dll:
                dl_iat[x] += [self.pe.OPTIONAL_HEADER.ImageBase + self.pe.sections[0].VirtualAddress + i * 0x10]
                master_byte_array += pack("@I", dl_iat[x][i])
                i += 1
            # не забываем про нультерминатор
            dl_iat[x] += [0]
            master_byte_array += pack("@I", 0)

            dl_idt[x].pINT = offset_after_dlidt + len(master_byte_array)

            i = 0
            offset_after_dlint = dl_idt[x].pINT + 4 * (
                    num_functions_per_dll + 1)
            dl_int += [[]]
            while i < num_functions_per_dll:
                dl_int[x] += [offset_after_dlint]
                i += 1
            dl_int[x] += [0]
            # NOTE выравнивание RVA на 2 взято из mspaint
            i = 0
            dl_hint_names += [[]]
            while i < num_functions_per_dll:
                dl_int[x][i] += len(dl_hint_names[x])
                dl_hint_names[x] += ['\x00', '\x00']  # hint нультерминатор
                random_func = random_functions_list[x][randint(0, len(random_functions_list) - 1)]
                dl_hint_names[x] += list(random_func)
                dl_hint_names[x] += ['\x00']  # null terminator (FIXME: confirm this is necessary?)
                if (len(random_func) + 1) % 2:
                    dl_hint_names[x] += ['\x00', '\x00', '\x00']
                i += 1

            i = 0
            for num in dl_int[x]:
                # FIXME: this could be the source for some 64 bit incompat. try condition @Q later
                master_byte_array += pack("@I", num)
            master_byte_array += dl_hint_names[x]
            x += 1

        # завершаем заполнение
        dlidt_bytes = []
        i = 0
        while i <= num_delay_load_entries:
            d = dl_idt[i]
            dlidt_bytes += list(d.__pack__())
            i += 1

        file_data_len_before_inserts = len(file_data)
        file_data += dlidt_bytes

        file_data += master_byte_array

        total_section_size = len(dlidt_bytes) + len(master_byte_array)
        nop_str = ['\x90'] * (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))

        file_data += nop_str

        # Вставляем section header
        offset_after_sect_hdr = self.pe.sections[-1].get_file_offset() + sect_hdr_size

        tmp_section.set_file_offset(offset_after_sect_hdr)
        tmp_section.Name = ".dload"
        tmp_section.Misc_VirtualSize = total_section_size

        tmp_section.SizeOfRawData = total_section_size + (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))
        tmp_section.VirtualAddress = existing_last_section_end_va

        tmp_section.PointerToRawData = file_data_len_before_inserts + self.pe.OPTIONAL_HEADER.FileAlignment
        tmp_section.Characteristics = 0x40000040

        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = list(tmp_section.__pack__())
        offset_after_sect_hdr += sect_hdr_size

        nop_str = ['\x90'] * (self.pe.OPTIONAL_HEADER.FileAlignment - sect_hdr_size)

        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = nop_str

        self.pe.OPTIONAL_HEADER.SizeOfImage = (total_delay_load_data_size_for_everything + tmp_section.VirtualAddress)
        self.pe.OPTIONAL_HEADER.SizeOfHeaders += sect_hdr_size

        for section in self.pe.sections:
            section.PointerToRawData += self.pe.OPTIONAL_HEADER.FileAlignment

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].VirtualAddress = tmp_section.VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[13].Size = len(dlidt_bytes)
        if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress:
            self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress += self.pe.OPTIONAL_HEADER.FileAlignment

        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

        for structure in self.pe.__structures__:

            offset = structure.get_file_offset()
            if offset >= tmp_section.get_file_offset():
                structure.set_file_offset(offset + self.pe.OPTIONAL_HEADER.FileAlignment)

            offset = structure.get_file_offset()
            struct_data = list(structure.__pack__())
            file_data[offset:offset + len(struct_data)] = struct_data

        new_file_data: bytes = mixed_list_to_bytes(file_data)
        return new_file_data

    def create_exports(self, random_funcs_num, random_functions: list) -> bytes:
        """
        Функция создает новую секцию с экспортами
        :param random_funcs_num: количество функций экспорта
        :param random_functions: случайные имена функций
        :return: аналогично
        """
        if not self.pe.is_dll():
            raise ValueError("if not self.pe.is_dll()")

        file_data = list(self.pe.__data__)
        file_data_len_before_inserts = len(file_data)

        self.pe.FILE_HEADER.NumberOfSections += 1
        exported_func_names = []
        i = 0
        while i < random_funcs_num:
            index = randint(0, len(random_functions) - 1)
            while random_functions[index] in exported_func_names:
                index = randint(0, len(random_functions) - 1)
            exported_func_names.append(random_functions[index])
            i += 1

        tmp_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__, pe=self.pe)

        sect_hdr_size = self.pe.sections[0].sizeof()
        tmp_section.__unpack__("\0" * sect_hdr_size)

        existing_last_section_end_va = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize
        if existing_last_section_end_va % 1000:
            existing_last_section_end_va += (0x1000 - existing_last_section_end_va % 0x1000)

        master_byte_array = []
        self.pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfNames += random_funcs_num  # TODO add in the existing entries
        self.pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions += random_funcs_num
        self.pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfFunctions = existing_last_section_end_va

        # получаем начало .text секции, чтобы сделать адреса более правдоподобными
        text_start = self.pe.sections[0].VirtualAddress
        text_end = text_start + self.pe.sections[0].Misc_VirtualSize
        eat = []
        i = 0
        while i < random_funcs_num:
            eat += [randint(text_start, text_end)]
            # FIXME: this could be the source for some 64 bit incompat. try condition @Q later
            master_byte_array += pack("@I", eat[i])
            i += 1

        exported_func_names.sort()
        # export_names = []
        name_ordinals = []
        ENT = []
        offset = 0
        i = 0
        while i < random_funcs_num:
            name_ordinals += [i]
            ENT += [existing_last_section_end_va + len(master_byte_array)]
            master_byte_array += list(exported_func_names[i])
            master_byte_array += ['\x00']  # не забываем нультерминатор
            i += 1

        self.pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNames = existing_last_section_end_va + len(master_byte_array)
        for num in ENT:
            # FIXME: здесь и далее - возможно несовместимость с некоторыми x64 бинарями
            master_byte_array += pack("@I", num)
        self.pe.DIRECTORY_ENTRY_EXPORT.struct.AddressOfNameOrdinals = existing_last_section_end_va + len(
            master_byte_array)
        for num in name_ordinals:
            master_byte_array += pack("@H", num)
        # запишем все данные, которые собрали
        file_data += master_byte_array
        total_section_size = len(master_byte_array)

        # паддинг после вставленной секции
        nop_str = ['\x90'] * (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))
        file_data += nop_str

        # стандартным образом всталвем секцию в хедере
        offset_after_sect_hdr = self.pe.sections[-1].get_file_offset() + sect_hdr_size

        tmp_section.set_file_offset(offset_after_sect_hdr)
        tmp_section.Name = b'.ebata'
        tmp_section.Misc_VirtualSize = total_section_size
        # выравниваем данные до размера self.pe.OPTIONAL_HEADER.FileAlignment
        tmp_section.SizeOfRawData = total_section_size + (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))
        tmp_section.VirtualAddress = existing_last_section_end_va
        # изменяем данные о конце файла
        tmp_section.PointerToRawData = file_data_len_before_inserts + self.pe.OPTIONAL_HEADER.FileAlignment
        tmp_section.Characteristics = 0x40000040

        # вставляем секцию
        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = list(tmp_section.__pack__())
        offset_after_sect_hdr += sect_hdr_size

        # паддинг
        nop_str = ['\x90'] * (self.pe.OPTIONAL_HEADER.FileAlignment - sect_hdr_size)
        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = nop_str

        # обновим на всякий случай
        self.pe.OPTIONAL_HEADER.SizeOfImage = (tmp_section.VirtualAddress + tmp_section.Misc_VirtualSize)
        self.pe.OPTIONAL_HEADER.SizeOfHeaders += sect_hdr_size

        # обновим PointerToRawData
        for section in self.pe.sections:
            section.PointerToRawData += self.pe.OPTIONAL_HEADER.FileAlignment

        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

        # обновим оффсеты структур
        for structure in self.pe.__structures__:

            offset = structure.get_file_offset()
            if offset >= tmp_section.get_file_offset():
                structure.set_file_offset(offset + self.pe.OPTIONAL_HEADER.FileAlignment)

            offset = structure.get_file_offset()
            struct_data = list(structure.__pack__())
            file_data[offset:offset + len(struct_data)] = struct_data

        new_file_data: bytes = mixed_list_to_bytes(file_data)
        return new_file_data


    def create_tls(self, random_callback_addresses: List[int]) -> bytes:
        """
        Создает новую секцию с tls директорией
        :param random_callback_addresses: случайные адреса для коллбеков в структуре
        :return: аналогично
        """
        file_data = list(self.pe.__data__)
        # указатель pointerToRawData
        file_data_len_before_inserts = len(file_data)

        self.pe.FILE_HEADER.NumberOfSections += 1

        tls_dir = pefile.Structure(self.pe.__IMAGE_TLS_DIRECTORY_format__)
        tls_dir.__unpack__("\0" * tls_dir.sizeof())
        tmp_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__, pe=self.pe)
        if not tmp_section:
            raise ValueError("tmp_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__, pe=self)")

        sect_hdr_size = self.pe.sections[0].sizeof()
        tmp_section.__unpack__(b'\0' * sect_hdr_size)

        # получим va последней секции
        existing_last_section_end_va = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize
        # round up to the nearest 0x1000
        if existing_last_section_end_va % 1000:
            existing_last_section_end_va += (0x1000 - existing_last_section_end_va % 0x1000)

        master_byte_array = []
        # вставляем таблицу коллбеков сразу за секцией
        tls_dir.AddressOfCallBacks = self.pe.OPTIONAL_HEADER.ImageBase + existing_last_section_end_va + tls_dir.sizeof()

        i = 0
        while i < len(random_callback_addresses):
            # FIXME: this could be the source for some 64 bit incompat. try condition @Q later
            master_byte_array += pack("@I", random_callback_addresses[i])
            i += 1

        file_data += list(tls_dir.__pack__())
        file_data += master_byte_array
        total_section_size = tls_dir.sizeof() + len(master_byte_array)


        nop_str = ['\x90'] * (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))

        file_data += nop_str

        offset_after_sect_hdr = self.pe.sections[-1].get_file_offset() + sect_hdr_size

        tmp_section.set_file_offset(offset_after_sect_hdr)
        tmp_section.Name = ".tls"
        tmp_section.Misc_VirtualSize = total_section_size + 0x200


        tmp_section.SizeOfRawData = total_section_size + (
                self.pe.OPTIONAL_HEADER.FileAlignment - (total_section_size % self.pe.OPTIONAL_HEADER.FileAlignment))
        tmp_section.VirtualAddress = existing_last_section_end_va

        tmp_section.PointerToRawData = file_data_len_before_inserts + self.pe.OPTIONAL_HEADER.FileAlignment
        tmp_section.Characteristics = 0x40000040

        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = list(tmp_section.__pack__())
        offset_after_sect_hdr += sect_hdr_size

        nop_str = ['\x90'] * (self.pe.OPTIONAL_HEADER.FileAlignment - sect_hdr_size)

        file_data[offset_after_sect_hdr:offset_after_sect_hdr] = nop_str

        self.pe.OPTIONAL_HEADER.SizeOfImage = (tmp_section.VirtualAddress + tmp_section.Misc_VirtualSize)
        self.pe.OPTIONAL_HEADER.SizeOfHeaders += sect_hdr_size

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = tmp_section.VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = tmp_section.Misc_VirtualSize

        for section in self.pe.sections:
            section.PointerToRawData += self.pe.OPTIONAL_HEADER.FileAlignment

        self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()

        for structure in self.pe.__structures__:

            offset = structure.get_file_offset()
            if offset >= tmp_section.get_file_offset():
                structure.set_file_offset(offset + self.pe.OPTIONAL_HEADER.FileAlignment)

            offset = structure.get_file_offset()
            struct_data = list(structure.__pack__())
            file_data[offset:offset + len(struct_data)] = struct_data

        new_file_data: bytes = mixed_list_to_bytes(file_data)
        return new_file_data
