import telebot, time
from time import sleep

bot = telebot.TeleBot('TOKEN')

@bot.message_handler(commands=['start'])
def start(message):
    checkid = str(message.chat.id)
    checkid2 = str(message.from_user.id)
    if checkid == 'CHAT_ID':
        with open('news.txt', 'r') as file:
            res = ''
            while True:
                line = file.readline()
                if not line:
                    break
                res = str(res) + line
            bot.send_message(message.chat.id, 'Welcome!')
    else:
        print('permission denied')
chat_id = 'CHAT_ID'
while True:
    with open('news.txt', 'r') as file:
        res = ''
        while True:
            line = file.readline()
            if not line:
                break
            res = str(res) + line
    if str(res) != '':
        bot.send_message(chat_id, str(res))

        with open('news.txt', 'w') as file2:
            emtpy = ''
            file2.write(emtpy)
        sleep(900)
    else:
        sleep(900)

if __name__=='__main__':
    while True:
        try:
            bot.polling(non_stop=True, interval=0)
        except Exception as error:
            print(error)
            time.sleep(5)
            continue