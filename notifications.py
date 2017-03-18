#!/usr/bin/python3
'''
Created on Mar 7, 2017

@author: famez


This file is part of Intrusion Dectection System Project.

Intrusion Dectection System Project is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intrusion Dectection System Project is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intrusion Dectection System Project.  If not, see <http://www.gnu.org/licenses/>.


'''
import sys
import re
import os
from gi.repository import Notify


if __name__ == '__main__':
    notification_queue = "/tmp/notifications"
    try:
        os.mkfifo(notification_queue)
    except OSError as err:
        if(err.errno != 17): #Already created
            print ("Error")
            sys.exit(1)
    while(True):
        fifo = open(notification_queue, 'r')
        for line in fifo:
            Notify.init("Instruction Detection Service")
            Hello=Notify.Notification.new("IDS", line, "dialog-information")
            Hello.show()