import QtQuick 2.9
import QtQuick.Controls 2.3
import QtQuick.Window 2.2
import QtQuick.Layouts 1.3

Window {
    id: main_window
    visible: true
    width: 640
    height: 480
    minimumWidth: 640
    minimumHeight: 480
    maximumWidth: 640
    maximumHeight: 480
    color: "#ffffff"
    title: qsTr("PeButcher")


    function disableInput(text) {
        input.focus = false
        mouse_input.enabled = false
        input_rect.color = "#c5baba"
        input.readOnly = true
        input.text = qsTr(text)
    }

    function enableInput() {
        input.focus = false
        mouse_input.enabled = true
        input_rect.color = "#ffffff"
        input.readOnly = false
        input.text = qsTr("Enter the answer")
    }

    function disableNextButton(){
        next_button.color = "#c5baba"
        mouse_next.enabled = false
    }

    function enableNextButton(){
        next_button.color = "#ffffff"
        mouse_next.enabled = true
    }

    function callNextQuestion() {
        answer.text = " "
        round.cleanup_binary()
        var question_available = round.next_question_available()
        if (question_available) {
            question.text = round.next_question()
            question_num.text = round.get_question_num()
            var file_written = round.is_question_executable()
            if (file_written) {
                answer.text = qsTr(
                            "File " + round.get_question_file_name(
                                ) + " written into current working directory")
            }
        } else {
            disableInput("<- Click back")
            disableNextButton()
            question_num.text = " "
            question.text = qsTr("Congratulations! You've finished the round")
        }
    }

    function executeRound(num){
        round.round_init(num)
        enableInput()
        enableNextButton()
        callNextQuestion()
        score.text = "Score: 0"
        swipeView.setCurrentIndex(1)
    }

    SwipeView {
        id: swipeView
        orientation: Qt.Horizontal
        enabled: true
        interactive: false
        hoverEnabled: true
        focusPolicy: Qt.TabFocus
        anchors.fill: parent
        currentIndex: 0

        Item {
            id: main_item
            width: 640
            height: 480
            Image {
                id: image
                anchors.fill: parent
                source: "resources/main.jpg"

                Text {
                    id: overall_score
                    width: 506
                    color: "#ffffff"
                    text: qsTr("Select round:")
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 400
                    anchors.left: parent.left
                    anchors.leftMargin: 44
                    anchors.top: parent.top
                    anchors.topMargin: 47
                    textFormat: Text.AutoText
                    font.bold: true
                    verticalAlignment: Text.AlignTop
                    font.pixelSize: 25
                    objectName: "overall_score"
                }

                Rectangle {
                    id: round1_rect
                    width: 140
                    height: 120
                    color: "#ffffff"
                    anchors.top: parent.top
                    anchors.topMargin: 108
                    anchors.left: parent.left
                    anchors.leftMargin: 44
                    clip: false
                    transformOrigin: Item.Center
                    antialiasing: true
                    enabled: true

                    MouseArea {
                        id: mouse_round1
                        antialiasing: false
                        anchors.right: parent.right
                        anchors.rightMargin: 7
                        anchors.left: parent.left
                        anchors.leftMargin: 7
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        anchors.top: parent.top
                        anchors.topMargin: 6
                        acceptedButtons: Qt.LeftButton
                        onPressed: {
                            parent.color = "#f40f8f"
                        }
                        onReleased: {
                            parent.color = "#ffffff"
                            executeRound(0)
                        }

                        Image {
                            id: image1
                            transformOrigin: Item.Center
                            anchors.rightMargin: 0
                            anchors.bottomMargin: 0
                            anchors.leftMargin: 0
                            anchors.topMargin: 0
                            anchors.fill: parent
                            source: "resources/sub.jpg"

                            Text {
                                id: round1_text
                                color: "#ffffff"
                                text: qsTr("Round 1")
                                anchors.right: parent.right
                                anchors.rightMargin: 26
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 79
                                anchors.top: parent.top
                                anchors.topMargin: 8
                                font.bold: true
                                font.pixelSize: 17
                            }

                            Text {
                                id: round1_score
                                color: "#ffffff"
                                text: qsTr("Score: 0")
                                horizontalAlignment: Text.AlignHCenter
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 8
                                anchors.top: parent.top
                                anchors.topMargin: 77
                                wrapMode: Text.WordWrap
                                font.bold: true
                                font.pixelSize: 15
                                objectName: "round1_score"
                            }

                            Text {
                                id: text1
                                color: "#ffffff"
                                text: qsTr("DOS_HEADER FILE_HEADER")
                                anchors.right: parent.right
                                anchors.rightMargin: 24
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 43
                                anchors.top: parent.top
                                anchors.topMargin: 37
                                verticalAlignment: Text.AlignVCenter
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.WordWrap
                                font.pixelSize: 12
                            }
                        }
                    }
                }

                Rectangle {
                    id: round2_rect
                    y: 107
                    width: 140
                    height: 120
                    color: "#ffffff"
                    anchors.left: round1_rect.right
                    anchors.leftMargin: 67
                    anchors.top: parent.top
                    anchors.topMargin: 107
                    enabled: true
                    antialiasing: true
                    clip: false
                    MouseArea {
                        id: mouse_round2
                        anchors.right: parent.right
                        anchors.rightMargin: 7
                        anchors.left: parent.left
                        anchors.leftMargin: 7
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        anchors.top: parent.top
                        anchors.topMargin: 6

                        onPressed: {
                            parent.color = "#000000"
                        }
                        onReleased: {
                            parent.color = "#ffffff"
                        }

                        Image {
                            id: image2
                            anchors.rightMargin: 0
                            anchors.bottomMargin: 0
                            anchors.leftMargin: 0
                            anchors.topMargin: 0
                            anchors.fill: parent
                            Text {
                                id: round2_text
                                color: "#ffffff"
                                text: qsTr("Round 2")
                                anchors.right: parent.right
                                anchors.rightMargin: 26
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 79
                                anchors.top: parent.top
                                anchors.topMargin: 8
                                font.bold: true
                                font.pixelSize: 17
                            }

                            Text {
                                id: round2_score
                                y: 77
                                height: 23
                                color: "#ffffff"
                                text: qsTr("Score: 0")
                                horizontalAlignment: Text.AlignHCenter
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 8
                                anchors.top: parent.top
                                anchors.topMargin: 78
                                font.bold: true
                                wrapMode: Text.WordWrap
                                font.pixelSize: 15
                                objectName: "round2_score"
                            }

                            Text {
                                id: text2
                                color: "#ffffff"
                                text: qsTr("OPTIONAL_HEADER")
                                anchors.right: parent.right
                                anchors.rightMargin: 24
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 43
                                anchors.top: parent.top
                                anchors.topMargin: 37
                                font.underline: false
                                font.italic: false
                                font.bold: false
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                font.pixelSize: 12
                                wrapMode: Text.WordWrap
                            }
                            source: "resources/sub.jpg"
                        }
                    }
                    transformOrigin: Item.Center
                }

                Rectangle {
                    id: round3_rect
                    x: 459
                    y: 107
                    width: 140
                    height: 120
                    color: "#ffffff"
                    anchors.left: round2_rect.right
                    anchors.leftMargin: 68
                    anchors.top: parent.top
                    anchors.topMargin: 107
                    enabled: true
                    antialiasing: true
                    clip: false
                    MouseArea {
                        id: mouse_round3
                        anchors.right: parent.right
                        anchors.rightMargin: 7
                        anchors.left: parent.left
                        anchors.leftMargin: 7
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        anchors.top: parent.top
                        anchors.topMargin: 6
                        onPressed: {
                            parent.color = "#000000"
                        }
                        onReleased: {
                            parent.color = "#ffffff"
                        }
                        Image {
                            id: image3
                            anchors.rightMargin: 0
                            anchors.bottomMargin: 0
                            anchors.leftMargin: 0
                            anchors.topMargin: 0
                            anchors.fill: parent
                            Text {
                                id: round3_text
                                color: "#ffffff"
                                text: qsTr("Round 3")
                                anchors.right: parent.right
                                anchors.rightMargin: 26
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 79
                                anchors.top: parent.top
                                anchors.topMargin: 8
                                font.bold: true
                                font.pixelSize: 17
                            }

                            Text {
                                id: round3_score
                                y: 77
                                height: 23
                                color: "#ffffff"
                                text: qsTr("Score: 0")
                                horizontalAlignment: Text.AlignHCenter
                                anchors.right: parent.right
                                anchors.rightMargin: 8
                                anchors.left: parent.left
                                anchors.leftMargin: 8
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 8
                                anchors.top: parent.top
                                anchors.topMargin: 78
                                font.bold: true
                                wrapMode: Text.WordWrap
                                font.pixelSize: 15
                                objectName: "round3_score"
                            }

                            Text {
                                id: text3
                                color: "#ffffff"
                                text: qsTr("SECTION_HEADER")
                                anchors.right: parent.right
                                anchors.rightMargin: 24
                                anchors.left: parent.left
                                anchors.leftMargin: 26
                                anchors.bottom: parent.bottom
                                anchors.bottomMargin: 43
                                anchors.top: parent.top
                                anchors.topMargin: 37
                                horizontalAlignment: Text.AlignHCenter
                                verticalAlignment: Text.AlignVCenter
                                font.pixelSize: 12
                                wrapMode: Text.WordWrap
                            }
                            source: "resources/sub.jpg"
                        }
                    }
                    transformOrigin: Item.Center
                }

                Text {
                    id: author
                    x: 508
                    y: 453
                    color: "#ffffff"
                    text: qsTr("PeButcher by fuunyaka")
                    anchors.right: parent.right
                    anchors.rightMargin: 8
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 13
                    font.pixelSize: 12
                }
            }
        }

        Item {
            id: round_item
            width: 640
            height: 480

            Image {
                id: image_back2
                anchors.fill: parent
                z: 0
                fillMode: Image.PreserveAspectCrop
                source: "resources/main.jpg"

                Text {
                    id: score
                    color: "#f13775"
                    text: qsTr("Score: -100")
                    anchors.bottom: question.top
                    anchors.bottomMargin: 12
                    verticalAlignment: Text.AlignVCenter
                    anchors.left: question_num.right
                    anchors.leftMargin: 46
                    anchors.top: parent.top
                    anchors.topMargin: 57
                    font.bold: false
                    horizontalAlignment: Text.AlignLeft
                    styleColor: "#ffffff"
                    font.pixelSize: 30
                }

                Rectangle {
                    id: back_button
                    width: 57
                    height: 55
                    color: "#ffffff"
                    radius: 27
                    anchors.left: parent.left
                    anchors.leftMargin: 35
                    anchors.top: parent.top
                    anchors.topMargin: 43

                    MouseArea {
                        id: mouse_back
                        anchors.right: parent.right
                        anchors.rightMargin: -4
                        anchors.left: parent.left
                        anchors.leftMargin: -4
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: -3
                        anchors.top: parent.top
                        anchors.topMargin: -5
                        hoverEnabled: true
                        onPressed: {
                            parent.color = "#d20878"
                        }
                        onReleased: {
                            parent.color = "#ffffff"
                            round.cleanup_binary()
                            round.update_score()
                            swipeView.setCurrentIndex(0)
                        }
                    }

                    Image {
                        id: image_back
                        anchors.right: parent.right
                        anchors.rightMargin: -5
                        anchors.left: parent.left
                        anchors.leftMargin: -3
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: -4
                        anchors.top: parent.top
                        anchors.topMargin: -4
                        source: "resources/back.png"
                    }
                }

                Text {
                    id: const_text
                    color: "#ffffff"
                    text: qsTr("Answer:")
                    anchors.bottom: input_rect.top
                    anchors.bottomMargin: 6
                    anchors.left: parent.left
                    anchors.leftMargin: 121
                    anchors.top: parent.top
                    anchors.topMargin: 328
                    font.bold: true
                    font.pixelSize: 15
                }

                Rectangle {
                    id: next_button
                    width: 57
                    height: 55
                    color: "#ffffff"
                    radius: 27
                    anchors.top: parent.top
                    anchors.topMargin: 346
                    anchors.left: input_rect.right
                    anchors.leftMargin: 29
                    MouseArea {
                        id: mouse_next
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.right: parent.right
                        anchors.rightMargin: -4
                        anchors.left: parent.left
                        anchors.leftMargin: -4
                        hoverEnabled: true
                        anchors.bottomMargin: -3
                        anchors.topMargin: -5
                        onPressed: {
                            parent.color = "#d20878"
                        }
                        onReleased: {
                            parent.color = "#ffffff"
                            enableInput()
                            callNextQuestion()
                        }
                    }

                    Image {
                        id: image_next
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        anchors.right: parent.right
                        anchors.rightMargin: -5
                        source: "resources/next.png"
                        anchors.left: parent.left
                        anchors.leftMargin: -3
                        anchors.bottomMargin: -4
                        anchors.topMargin: -4
                    }
                }

                Rectangle {
                    id: input_rect
                    width: 358
                    height: 42
                    color: "#ffffff"
                    antialiasing: true
                    enabled: true
                    anchors.left: parent.left
                    anchors.leftMargin: 121
                    anchors.top: parent.top
                    anchors.topMargin: 352

                    TextInput {
                        id: input
                        color: "#817a7a"
                        text: qsTr("Enter the answer")
                        anchors.right: parent.right
                        anchors.rightMargin: 8
                        anchors.left: parent.left
                        anchors.leftMargin: 8
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        anchors.top: parent.top
                        anchors.topMargin: 8
                        enabled: true
                        antialiasing: true
                        font.capitalization: Font.MixedCase
                        clip: true
                        selectionColor: "#ffffff"
                        horizontalAlignment: Text.AlignLeft
                        font.pixelSize: 18

                        onAccepted: {
                            var correct = round.check_answer(input.text)
                            disableInput("Сlick next ->")
                            score.text = "Score: " + round.get_score(correct)
                            if (correct) {
                                answer.text = qsTr("Correct!")
                            } else {
                                answer.text = qsTr(
                                            "Nope! Correct answer: " + round.get_answer(
                                                ))
                            }
                        }

                        MouseArea {
                            id: mouse_input
                            anchors.fill: parent
                            onClicked: {
                                input.clear()
                                input.forceActiveFocus()
                            }
                        }
                    }
                }

                Text {
                    id: question
                    width: 442
                    height: 103
                    color: "#ffffff"
                    text: qsTr("Question here")
                    anchors.top: question_num.bottom
                    anchors.topMargin: 20
                    verticalAlignment: Text.AlignVCenter
                    anchors.left: parent.left
                    anchors.leftMargin: 121
                    enabled: false
                    wrapMode: Text.WordWrap
                    font.bold: true
                    font.family: "Arial"
                    font.pixelSize: 20
                    objectName: "question_text"
                }

                Text {
                    id: answer
                    width: 442
                    color: "#ffffff"
                    text: qsTr("Answer here")
                    anchors.bottom: const_text.top
                    anchors.bottomMargin: 13
                    anchors.left: parent.left
                    anchors.leftMargin: 121
                    anchors.top: question.bottom
                    anchors.topMargin: 6
                    enabled: false
                    wrapMode: Text.WordWrap
                    verticalAlignment: Text.AlignTop
                    horizontalAlignment: Text.AlignLeft
                    font.pixelSize: 20
                    objectName: "answer_text"
                }

                Text {
                    id: author2
                    x: 508
                    y: 453
                    color: "#ffffff"
                    text: qsTr("PeButcher by fuunyaka")
                    anchors.right: parent.right
                    anchors.rightMargin: 8
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: 13
                    font.pixelSize: 12
                }

                Text {
                    id: question_num
                    width: 243
                    height: 33
                    color: "#ffffff"
                    text: qsTr("Question 1:")
                    verticalAlignment: Text.AlignVCenter
                    font.bold: true
                    anchors.left: back_button.right
                    anchors.leftMargin: 29
                    anchors.top: parent.top
                    anchors.topMargin: 57
                    font.pixelSize: 20
                    objectName: "question_num"
                }
            }
        }
    }
}
