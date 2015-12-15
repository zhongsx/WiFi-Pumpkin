#The MIT License (MIT)
#Copyright (c) 2015-2016 mh4x0f P0cL4bs Team
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
#the Software, and to permit persons to whom the Software is furnished to do so,
#subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
#FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
#COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
#IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
#CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
from os import getcwd,path
from PyQt4.QtGui import *
from PyQt4.QtCore import *
from Core.config.Settings import frm_Settings
from Modules.utils import ThreadPopen


class frm_NetCredsLogger(QDialog):
    def __init__(self, parent = None):
        super(frm_NetCredsLogger, self).__init__(parent)
        self.setGeometry(0, 0, 550, 400)
        self.Main       = QVBoxLayout(self)
        self.owd        = getcwd()
        self.thread     = []
        self.config     = frm_Settings()
        self.loadtheme(self.config.XmlThemeSelected())
        self.center()
        self.Qui()

    def loadtheme(self,theme):
        sshFile=("Core/%s.qss"%(theme))
        with open(sshFile,"r") as fh:
            self.setStyleSheet(fh.read())

    def center(self):
        frameGm = self.frameGeometry()
        centerPoint = QDesktopWidget().availableGeometry().center()
        frameGm.moveCenter(centerPoint)
        self.move(frameGm.topLeft())

    def Start_Get_creds(self):
        self.listDns.clear()
        self.list_creds.clear()
        # Thread Capture logs
        creds = ThreadPopen(['tail','-f','Logs/credentials.log'])
        self.connect(creds,SIGNAL('Activated ( QString ) '), self.loggercreds)
        creds.setObjectName('Netcreds::Credentials')
        urls = ThreadPopen(['tail','-f','Logs/urls.log'])
        self.connect(urls,SIGNAL('Activated ( QString ) '), self.loggerurls)
        urls.setObjectName('Netcreds::Urls')
        if path.exists('Logs/credentials.log'):
            self.thread.append(creds)
            creds.start()
        if path.exists('Logs/urls.log'):
            self.thread.append(urls)
            urls.start()
        if not urls.isRunning():
            QMessageBox.warning(self,'error logger read','netcreds no logger found.')

    def loggercreds(self,data):
        self.list_creds.addItem(data)
        self.list_creds.scrollToBottom()
    def loggerurls(self,data):
        self.listDns.addItem(data)
        self.listDns.scrollToBottom()

    def exit_function(self):
        for i in self.thread:i.stop()
        self.deleteLater()
    def Qui(self):
        self.frm0 = QFormLayout(self)
        self.listDns = QListWidget(self)
        self.listDns.setAutoScroll(True)
        self.list_creds = QListWidget(self)
        self.list_creds.setAutoScroll(True)

        self.btn_getdata = QPushButton('Capture logs')
        self.btn_getdata.clicked.connect(self.Start_Get_creds)
        self.btn_exit = QPushButton('Exit')
        self.btn_exit.clicked.connect(self.exit_function)

        self.frm0.addRow(self.listDns)
        self.frm0.addRow(self.list_creds)

        self.frm0.addRow(self.btn_getdata)
        self.frm0.addRow(self.btn_exit)
        self.Main.addLayout(self.frm0)
        self.setLayout(self.Main)