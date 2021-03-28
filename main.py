import sys
import PyQt5.QtQml  as qml
from PyQt5.QtCore import QObject, pyqtSlot
from PyQt5.QtWidgets import QApplication

from pebutcher.base_round import Round, Question
from pebutcher.utils.helpers import write_score, read_score, rounds_in_config


class RoundView(QObject):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.round = None
        self.config_file = "config.txt"

        def change_score(*, round_num: int, score: int) -> None:
            last_score = read_score(round_num, self.config_file)
            if score >= last_score:
                object_name = 'round' + str(round_num + 1) + '_score'
                text_object: QObject = self.parent().findChild(QObject, object_name)
                text_prop = qml.QQmlProperty(text_object, "text")
                text_prop.write('Score: ' + str(score))
                write_score(round_num, self.config_file, score)

        def set_score(self) -> None:
            round_to_update = rounds_in_config(self.config_file)
            for num in range(0, round_to_update):
                last_score = read_score(num, self.config_file)
                change_score(round_num=num, score=last_score)

        self.score_updater = change_score
        set_score(self)

    @pyqtSlot(int)
    def round_init(self, round_num: int):
        self.round = Round(round_num)

    @pyqtSlot(result=str)
    def next_question(self) -> str:
        question_text = self.round.execute_next_question()
        return question_text

    @pyqtSlot(str, result=bool)
    def check_answer(self, student_answer: str) -> bool:
        def y_n_to_bool_str(answer: str) -> str:
            if answer == 'y':
                return 'True'
            elif answer == 'n':
                return 'False'
            else:
                return answer

        lower_answer = student_answer.lower()
        return self.round.check_answer(y_n_to_bool_str(lower_answer))

    @pyqtSlot(result=str)
    def get_answer(self) -> str:
        def bool_str_to_y_n(answer):
            if answer == 'True':
                return 'Yes'
            elif answer == 'False':
                return 'No'
            else:
                return answer

        question: Question = self.round.active_question
        return bool_str_to_y_n(question.get_answer())

    @pyqtSlot(bool, result=str)
    def get_score(self, is_correct: bool) -> str:
        score: int = self.round.change_score(is_correct)
        return str(score)

    @pyqtSlot(result=bool)
    def next_question_available(self) -> bool:
        if self.round.is_questions_remaining():
            return True
        else:
            return False

    @pyqtSlot()
    def update_score(self) -> None:
        self.score_updater(round_num=self.round.round_num, score=self.round.score)

    @pyqtSlot(result=bool)
    def is_question_executable(self) -> bool:
        return self.round.context_executed

    @pyqtSlot(result=str)
    def get_question_file_name(self) -> str:
        question_text = 'question' + str(self.round.next_question_id - 1)
        round_text = 'round' + str(self.round.round_num + 1)
        text = round_text + '_' + question_text
        return text

    @pyqtSlot(result=str)
    def get_question_num(self) -> str:
        return 'Question: ' + str(self.round.next_question_id - 1)

    @pyqtSlot()
    def cleanup_binary(self) -> None:
        self.round.celeanup_previous_binary()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    engine = qml.QQmlApplicationEngine()
    context = engine.rootContext()
    context.setContextProperty('main', engine)
    engine.load('pebutcher/qml/main.qml')
    win = engine.rootObjects()[0]

    round = RoundView(parent=win)
    context.setContextProperty('round', round)
    win.show()
    sys.exit(app.exec_())
