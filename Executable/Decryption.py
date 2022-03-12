# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file './UI/Decryption.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(929, 480)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.line = QtWidgets.QFrame(self.centralwidget)
        self.line.setGeometry(QtCore.QRect(10, 210, 911, 20))
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(20, 30, 55, 16))
        self.label.setScaledContents(False)
        self.label.setObjectName("label")
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(130, 20, 621, 191))
        self.textEdit.setObjectName("textEdit")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(820, 150, 93, 28))
        self.pushButton.setObjectName("pushButton")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(20, 320, 55, 16))
        self.label_2.setObjectName("label_2")
        self.textEdit_2 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_2.setGeometry(QtCore.QRect(130, 240, 631, 171))
        self.textEdit_2.setObjectName("textEdit_2")
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(800, 30, 101, 22))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 929, 26))
        self.menubar.setObjectName("menubar")
        self.menuEncrypt = QtWidgets.QMenu(self.menubar)
        self.menuEncrypt.setObjectName("menuEncrypt")
        self.menuDecrypt = QtWidgets.QMenu(self.menubar)
        self.menuDecrypt.setObjectName("menuDecrypt")
        self.menuKey_Encrypt = QtWidgets.QMenu(self.menubar)
        self.menuKey_Encrypt.setObjectName("menuKey_Encrypt")
        self.menuKey_Decrypt = QtWidgets.QMenu(self.menubar)
        self.menuKey_Decrypt.setObjectName("menuKey_Decrypt")
        self.menuStrong_password = QtWidgets.QMenu(self.menubar)
        self.menuStrong_password.setObjectName("menuStrong_password")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.menubar.addAction(self.menuEncrypt.menuAction())
        self.menubar.addAction(self.menuDecrypt.menuAction())
        self.menubar.addAction(self.menuKey_Encrypt.menuAction())
        self.menubar.addAction(self.menuKey_Decrypt.menuAction())
        self.menubar.addAction(self.menuStrong_password.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "INPUT"))
        self.pushButton.setText(_translate("MainWindow", "Decrypt"))
        self.label_2.setText(_translate("MainWindow", "OUTPUT"))
        self.comboBox.setItemText(0, _translate("MainWindow", "SHA256"))
        self.comboBox.setItemText(1, _translate("MainWindow", "SHA224"))
        self.comboBox.setItemText(2, _translate("MainWindow", "SHA512"))
        self.comboBox.setItemText(3, _translate("MainWindow", "SHA384"))
        self.comboBox.setItemText(4, _translate("MainWindow", "SHA1"))
        self.comboBox.setItemText(5, _translate("MainWindow", "SHA3_512"))
        self.comboBox.setItemText(6, _translate("MainWindow", "SHA3_384"))
        self.comboBox.setItemText(7, _translate("MainWindow", "SHA3_256"))
        self.comboBox.setItemText(8, _translate("MainWindow", "SHA3_224"))
        self.comboBox.setItemText(9, _translate("MainWindow", "SHAKE256"))
        self.comboBox.setItemText(10, _translate("MainWindow", "SHAKE128"))
        self.comboBox.setItemText(11, _translate("MainWindow", "SHA512_224"))
        self.comboBox.setItemText(12, _translate("MainWindow", "SHA512_256"))
        self.comboBox.setItemText(13, _translate("MainWindow", "MD2"))
        self.comboBox.setItemText(14, _translate("MainWindow", "MD4"))
        self.comboBox.setItemText(15, _translate("MainWindow", "MD5"))
        self.comboBox.setItemText(16, _translate("MainWindow", "MD5_SHA1"))
        self.comboBox.setItemText(17, _translate("MainWindow", "WHIRLPOOL"))
        self.comboBox.setItemText(18, _translate("MainWindow", "RIPEMD_160"))
        self.comboBox.setItemText(19, _translate("MainWindow", "BLAKE2S"))
        self.comboBox.setItemText(20, _translate("MainWindow", "BLAKE2B"))
        self.comboBox.setItemText(21, _translate("MainWindow", "SM3"))
        self.comboBox.setItemText(22, _translate("MainWindow", "ADLER32"))
        self.comboBox.setItemText(23, _translate("MainWindow", "CR32"))
        self.menuEncrypt.setTitle(_translate("MainWindow", "Encrypt"))
        self.menuDecrypt.setTitle(_translate("MainWindow", "Decrypt"))
        self.menuKey_Encrypt.setTitle(_translate("MainWindow", "Key Encrypt"))
        self.menuKey_Decrypt.setTitle(_translate("MainWindow", "Key Decrypt"))
        self.menuStrong_password.setTitle(_translate("MainWindow", "Strong password"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
