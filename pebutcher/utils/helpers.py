from pathlib import Path
from typing import Tuple, List
from random import randint
from os import remove, path


def gen_binary_name(*, round_num: int, question_num: int) -> str:
    return 'round' + str(round_num) + '_question' + str(question_num)


def get_file_path(file: str) -> str:
    try:
        path = Path('./').rglob(file).__next__()
    except StopIteration:
        path = ""
    return str(path)


def create_if_needed(config: str) -> str:
    if get_file_path(config) == '':
        open(config, 'a').close()
    return get_file_path(config)


def rounds_in_config(config: str) -> int:
    config_path = create_if_needed(config)
    with open(config_path, "r") as file:
        config_data = file.read()
    return len(config_data.splitlines())


def read_score(round_num: int, config: str) -> int:
    config_path = create_if_needed(config)
    with open(config_path, "r") as file:
        config_data = file.read()
    rounds_data: list = config_data.splitlines()
    round_str = 'round' + str(round_num) + ':'
    for entry in rounds_data:
        if round_str in entry:
            return int(entry[len(round_str):])
    return 0


def write_score(round_num: int, config: str, score: int) -> None:
    config_path = create_if_needed(config)
    last_score = read_score(round_num, config)
    with open(config_path, "r") as file:
        config_data = file.read()
    rounds_data: list = config_data.splitlines()
    round_str = 'round' + str(round_num) + ':' + str(score)
    if last_score == 0:
        rounds_data.append(round_str)
    else:
        rounds_data[round_num] = round_str
    with open(config_path, "wt") as file:
        file.write('\n'.join(rounds_data))
        file.write('\n')


def write_file(*, file_name: str, data: bytes) -> None:
    with open(file_name, "wb+") as file:
        file.write(data)


def delete_file(file_name: str) -> None:
    full_file_name: str = get_file_path(file_name)
    if path.exists(full_file_name):
        remove(full_file_name)


def mixed_list_to_bytes(arg: list) -> bytes:
    ret: List[int] = []
    for element in arg:
        if isinstance(element, int):
            ret.append(element)
        elif isinstance(element, bytes):
            ret.append(element[0])
        elif isinstance(element, str):
            ret.append(ord(element))
    return bytes(ret)


def select_random_pe() -> Tuple[str, str, str]:
    switch = randint(0, 3)
    if switch == 0:
        pe_path = get_file_path("exports/template32.exe")
        suffix = '.exe'
        bin_bits = '32'
    elif switch == 1:
        pe_path = get_file_path("exports/template64.exe")
        suffix = '.exe'
        bin_bits = '64'
    elif switch == 2:
        pe_path = get_file_path("exports/template32.dll")
        suffix = '.dll'
        bin_bits = '32'
    else:
        pe_path = get_file_path("exports/template64.dll")
        suffix = '.dll'
        bin_bits = '64'

    return pe_path, suffix, bin_bits
