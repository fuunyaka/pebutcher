from collections import namedtuple
from typing import List, NamedTuple, Callable
from random import randint
from json import load
from pebutcher.utils.helpers import get_file_path, gen_binary_name, delete_file


class Question:
    def __init__(self, *, questions: List[str], answers: List[str], executable_context: Callable[[int], str] = None,
                 award: int = 100) -> None:
        self.question_variants = questions
        self.answer_variants = answers
        self.active_variant = 0
        self.question = questions[0]
        self.answer = answers[0]
        self.award = award
        self.executable_context = executable_context

    def __str__(self) -> str:
        return self.question

    def __int__(self) -> int:
        return self.award

    def get_random_question_variant(self) -> str:
        self.active_variant = randint(0, len(self.question_variants) - 1)
        self.question = self.question_variants[self.active_variant]
        self.answer = self.answer_variants[self.active_variant]
        return self.question

    def get_answer(self) -> str:
        return self.answer

    def answer_is_none(self):
        if self.answer == 'None':
            return True
        else:
            return False

    def check_answer(self, student_answer: str) -> bool:
        if self.answer == student_answer:
            return True
        else:
            return False

    def call_executable_context(self) -> str:
        self.answer = self.executable_context(self.active_variant)
        return self.answer


class Round:
    def __init__(self, round_num: int, score: int = 0) -> None:
        self.round_num = round_num
        self.score = score
        self.next_question_id = 0
        self.questions: List[Question] = []
        self.active_question = None
        self.context_executed = False

        questions_file = get_file_path('round' + str(self.round_num) + '_questions.json')
        with open(questions_file) as file:
            questions_json = load(file)

        round_key = 'round' + str(self.round_num)
        for question in questions_json[round_key]:
            variants: List[str] = []
            for variant in questions_json[round_key][question]['variants']:
                variants.append(questions_json[round_key][question]['variants'][variant])
            answers: List[str] = []
            for answer in questions_json[round_key][question]['answers']:
                answers.append(questions_json[round_key][question]['answers'][answer])

            import_name = 'pebutcher.rounds.round' + str(self.round_num) + '.questions.executable_context'
            current_exec_context = __import__(import_name, fromlist=[question])
            if hasattr(current_exec_context, question):
                exec_ctx = getattr(current_exec_context, question)
            else:
                exec_ctx = None
            self.questions.append(Question(questions=variants, answers=answers, executable_context=exec_ctx))

    def __int__(self) -> int:
        return self.score

    def change_score(self, answer_is_correct: bool) -> int:
        if answer_is_correct:
            self.score += self.active_question.award
        else:
            self.score -= self.active_question.award
        return self.score

    def celeanup_previous_binary(self) -> None:
        if self.context_executed:
            binary_name = gen_binary_name(round_num=self.round_num + 1, question_num=self.next_question_id - 1)
            binary_name += '.*'
            delete_file(binary_name)

    def execute_next_question(self) -> str:
        self.active_question: Question = self.questions[self.next_question_id]
        question_text: str = self.active_question.get_random_question_variant()
        if self.active_question.answer_is_none():
            self.context_executed = True
            self.active_question.call_executable_context()
        else:
            self.context_executed = False
        self.next_question_id += 1
        return question_text

    def check_answer(self, student_answer: str) -> bool:
        return self.active_question.check_answer(student_answer)

    def is_questions_remaining(self) -> bool:
        if self.next_question_id >= len(self.questions):
            self.context_executed = False
            return False
        else:
            return True
