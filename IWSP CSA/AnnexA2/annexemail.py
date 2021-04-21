import smtplib
from email.message import EmailMessage
from datetime import datetime


def send_email(body, subject):
    email_from = 'csajoshemail@gmail.com'
    email_to = ['jshwwe@gmail.com']
    password = '-redacted-'

    message = EmailMessage()
    message['From'] = email_from
    message['To'] = email_to

    message['Subject'] = subject
    message.set_content(body)

    with open('phish.csv', 'rb') as file:
        message.add_attachment(file.read(),
                               maintype="text",
                               subtype="csv",
                               filename='phish-' + datetime.today().strftime('%Y-%m-%d') + '.csv')

    with open('deface.csv', 'rb') as file:
        message.add_attachment(file.read(),
                               maintype="text",
                               subtype="csv",
                               filename='deface-' + datetime.today().strftime('%Y-%m-%d') + '.csv')

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)

    server.login(email_from, password)
    server.send_message(message)
    print("Email Successfully Sent!")