from typing import Tuple, List
from random import randint, getrandbits
from time import time
from pebutcher.utils.peworker import PeWorker
from pebutcher.utils.helpers import select_random_pe, write_file, gen_binary_name


def question0(vairant: int) -> str:
    return ""


def question1(variant: int) -> str:
    pe_path, suffix, bin_bits = select_random_pe()
    executable = PeWorker(pe_path)

    bytes: List[str] = ['\x41'] * 4 * randint(0, 128)
    buffer: bytes = executable.randomize_nt_header_location(bytes, executable.pe.DOS_HEADER.e_lfanew)
    outfile = gen_binary_name(round_num=1, question_num=1) + suffix
    write_file(file_name=outfile, data=buffer)

    if variant == 3:
        answer = hex(executable.pe.DOS_HEADER.e_lfanew - list(executable.pe.DOS_HEADER.__pack__()).__len__())
    else:
        answer = hex(executable.pe.DOS_HEADER.e_lfanew)

    return answer


def question2(variant: int) -> str:
    pe_path, suffix, bin_bits = select_random_pe()
    executable = PeWorker(pe_path)

    current_time = int(time())
    executable.pe.FILE_HEADER.TimeDateStamp = randint(0, current_time)

    outfile = gen_binary_name(round_num=1, question_num=2) + suffix
    try:
        executable.pe.write(filename=outfile)
    except:
        pass  # TODO добавить отрисовку в окно

    binary_year = 1970 + int(executable.pe.FILE_HEADER.TimeDateStamp / 31556926)
    current_year = 1970 + int(current_time / 31556926)

    if variant == 1:
        answer = hex(executable.pe.FILE_HEADER.TimeDateStamp)
    elif variant == 2:
        answer = str(current_year - binary_year)
    else:
        answer = str(binary_year)

    return answer


def question3(variant: int) -> str:
    pe_path, suffix, bin_bits = select_random_pe()
    executable = PeWorker(pe_path)
    outfile = gen_binary_name(round_num=1, question_num=3) + suffix

    executable.pe.write(filename=outfile)

    if bin_bits == '32':
        bin_type = 'pe32'
    else:
        bin_type = 'pe32+'

    if variant == 0:
        answer = bin_bits
    elif variant == 1:
        answer = bin_type
    else:
        if bin_bits == '32':
            answer = '0x014c'
        else:
            answer = '0x8664'

    return answer


def question4(variant: int) -> str:
    pe_path, suffix, bin_bits = select_random_pe()
    executable = PeWorker(pe_path)

    extra_sections_number = randint(1, 5)
    current_sections_number = executable.pe.FILE_HEADER.NumberOfSections
    total_sections = extra_sections_number + current_sections_number

    buffer: bytes = executable.modify_sections(total_sections, True)
    outfile = gen_binary_name(round_num=1, question_num=4) + suffix
    write_file(file_name=outfile, data=buffer)

    answer = executable.pe.FILE_HEADER.NumberOfSections
    return str(answer)


def question5(variant: int) -> str:
    pe_path, suffix, bin_bits = select_random_pe()
    executable = PeWorker(pe_path)

    if suffix == '.dll':
        is_dll = True
    else:
        is_dll = False

    flags_set_number = 0
    if is_dll:
        flags_set_number += 1

    if bool(getrandbits(1)):
        executable.pe.FILE_HEADER.Characteristics |= 0x20
        executable.pe.FILE_HEADER.Characteristics &= 0xffff
        is_large_aware = True
        flags_set_number += 1
    else:
        executable.pe.FILE_HEADER.Characteristics |= ~0x20
        executable.pe.FILE_HEADER.Characteristics &= 0xffff
        is_large_aware = False

    if bool(getrandbits(1)):
        executable.pe.FILE_HEADER.Characteristics |= 0x100
        executable.pe.FILE_HEADER.Characteristics &= 0xffff
        is_32_characteristics = True
        flags_set_number += 1
    else:
        executable.pe.FILE_HEADER.Characteristics |= ~0x100
        executable.pe.FILE_HEADER.Characteristics &= 0xffff
        is_32_characteristics = False

    outfile = gen_binary_name(round_num=1, question_num=5) + suffix
    executable.pe.write(filename=outfile)

    if variant == 0 or variant == 1:
        answer = True
    elif variant == 2 or variant == 3:
        answer = is_dll
    elif variant == 4 or variant == 5:
        answer = is_large_aware
    elif variant == 6:
        answer = is_32_characteristics
    elif variant == 7:
        answer = hex(executable.pe.FILE_HEADER.Characteristics)
    else:
        answer = flags_set_number

    return str(answer)
