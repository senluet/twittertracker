# -*- coding: utf8 -*-
from pyuseragents import random as random_useragent
from requests import Session
from random import randint
from time import sleep, time
from msvcrt import getch
from os import system
from ctypes import windll
from urllib3 import disable_warnings
from loguru import logger
from sys import stderr, exit
from json import loads, load
from bs4 import BeautifulSoup
from multiprocessing.dummy import Pool
from re import match
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from re import findall

disable_warnings()


def clear(): return system('cls')


logger.remove()
logger.add(stderr,
           format="<white>{time:HH:mm:ss}</white> | <level>"
           "{level: <8}</level> | <cyan>"
           "{line}</cyan> - <white>{message}</white>")
windll.kernel32.SetConsoleTitleW('TwitterTest')

wallets_addresses = None
all_images_files = []

with open('countries.json', 'r', encoding='utf-8') as file:
    file_list = load(file)

files = [str(f.absolute())
         for f in Path('Cookies').glob("**/*")
         if Path(str(f.absolute())).suffix == '.txt']

with open('accounts.txt', 'r', encoding='utf-8') as file:
    accounts_cookies = file.read()\
                        .replace(''''"''', ''''\\"''')\
                        .replace('''"\'''', '''\\"\'''')\
                        .replace("'", '"')\
                        .replace("False", "false")\
                        .replace("True", "true")\
                        .replace("None", "null")\
                        .splitlines()

for current_folder in files:
    with open(current_folder, 'r', encoding='utf-8') as file:
        current_cookie = file.read().replace('	', ' ')

        if len(current_cookie) > 0:
            accounts_cookies.append(current_cookie)

logger.success(f'Успешно загружено {len(accounts_cookies)} аккаунтов\n')

user_action = int(14)
print('')

threads = int(1)


def random_with_N_digits(n):
    range_start = 10**(n-1)
    range_end = (10**n)-1
    return randint(range_start, range_end)


def handle_errors(data):
    if not data.ok:
        raise Wrong_Response(data)

    try:
        if loads(data.text).get('errors'):
            if loads(data.text)['errors'][0]['message'] ==\
                    'Your account is suspended and is not permitted to access this feature.':
                raise Own_Account_Suspended('')
            else:
                raise Wrong_Response(data)

        reason = loads(data.text)['data']['user']['result']['reason']
        raise Account_Suspended(reason)

    except Exception:
        return


class Wrong_Response(BaseException):
    pass


class Wrong_UserAgent(BaseException):
    pass


class Account_Suspended(BaseException):
    pass


class Own_Account_Suspended(BaseException):
    pass


class App():
    def __init__(self, cookies_str, current_proxy):
        self.current_proxy = current_proxy
        self.cookies_str = cookies_str
        self.lang = ''
        self.session = Session()
        self.session.headers.update({
            'user-agent': random_useragent(),
            'Origin': 'https://mobile.twitter.com',
            'Referer': 'https://mobile.twitter.com/',
            'x-twitter-active-user': 'yes',
            'x-twitter-auth-type': 'OAuth2Session',
            'x-twitter-client-language': 'en',
            'content-type': 'application/json',
            'accept': '*/*',
            'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7',
            })

        self.session_unblock = Session()
        self.session_unblock.headers.update({
            'accept': 'text/html,application/xhtml+xml,application/'
                      'xml;q=0.9,image/avif,image/webp,image/'
                      'apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language': 'ru,en;q=0.9,vi;q=0.8,es;q=0.7',
            'referer': 'https://twitter.com/i/flow/login',
            'cache-control': 'max-age=0',
            'upgrade-insecure-requests': '1',
            'user-agent': self.session.headers['user-agent']
        })


    def get_values(self):
        for _ in range(15):
            try:
                r = self.session.get('https://twitter.com/home',
                                     verify=False)

                handle_errors(r)

                url_to_get_query_ids = BeautifulSoup(r.text, 'lxml')\
                    .find_all('link',
                              {'rel': 'preload', 'as': 'script', 'crossorigin': 'anonymous'})[-1]\
                    .get('href')

                r = self.session.get(url_to_get_query_ids,
                                     verify=False)

                handle_errors(r)

                self.queryIdforSubscribe = r.text.split('",operationName:"TweetResultByRestId')[0]\
                                                 .split('"')[-1]
                self.queryIdforRetweet = r.text.split('",operationName:"CreateRetweet')[0]\
                                               .split('"')[-1]
                self.queryIdforLike = r.text.split('",operationName:"FavoriteTweet')[0]\
                                            .split('"')[-1]
                self.queryIdforComment = r.text.split('",operationName:"CreateTweet"')[0]\
                                               .split('"')[-1]
                self.queryIdforFollowers = r.text.split('",operationName:"Followers')[0]\
                                                 .split('"')[-1]
                self.queryIdforUserByScreenName = r.text.split('",operationName:'
                                                               '"UserByScreenName')[0]\
                                                        .split('"')[-1]
                self.queryIdforCreateTweet = r.text.split('",operationName:"CreateTweet"')[0]\
                                                   .split('"')[-1]
                self.queryIdforDataSaverMode = r.text.split('"A",operationName:"DataSaverMode"')[0]\
                                                     .split('"')[-1]
                self.action_refresh = r.text.split('ACTION_REFRESH",i="')[-1]\
                                            .split('"')[0]
                bearer_token = 'Bearer ' + r.text.split('r="ACTION_FLUSH"')[-1]\
                                                 .split(',s="')[1]\
                                                 .split('"')[0]

                if match('^[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+ '
                         '[а-яА-ЯёЁa-zA-Z0-9._/"=%# |+,:\}\{\-\n\r]+',
                         self.cookies_str):

                    for current_cookie_value in self.cookies_str.split('\n'):
                        self.session.cookies[current_cookie_value.strip().split()[5]]\
                            = current_cookie_value.strip().split()[6]
                        self.session_unblock.cookies[current_cookie_value.strip().split()[5]]\
                            = current_cookie_value.strip().split()[6]

                        if current_cookie_value.strip().split()[5] == 'ct0':
                            csrf_token = current_cookie_value.strip().split()[6]

                        if current_cookie_value.strip().split()[5] == 'lang':
                            self.lang = current_cookie_value.strip().split()[6]

                elif self.cookies_str[:1] == '[' and self.cookies_str[-1:] == ']':
                    for current_cookie_value in \
                            loads('[' + self.cookies_str.split('[')[-1]
                                  .replace(''''"''', ''''\\"''')
                                  .replace('''"\'''', '''\\"\'''')
                                  .replace("'", '"')
                                  .replace("False", "false")
                                  .replace("True", "true")
                                  .replace("None", "null")):

                        self.session.cookies[current_cookie_value['name']]\
                             = current_cookie_value['value']

                        self.session_unblock.cookies[current_cookie_value['name']]\
                            = current_cookie_value['value']

                        if current_cookie_value['name'] == 'ct0':
                            csrf_token = current_cookie_value['value']

                        elif current_cookie_value['name'] == 'lang':
                            self.lang = current_cookie_value['value']

                else:
                    self.session.headers.update({'cookie': self.cookies_str})
                    self.session_unblock.headers.update({'cookie': self.cookies_str})
                    csrf_token = self.cookies_str.split('ct0=')[-1].split(';')[0]

                    self.lang = self.cookies_str.split('lang=')[-1].split(';')[0]

                self.session.headers.update({
                    'authorization': bearer_token,
                    'x-csrf-token': csrf_token})

                self.first_step()

            except Exception as error:
                logger.error(f'Ошибка при получении начальных параметров: {str(error)}')
                continue

            except Wrong_Response:
                new_ua = random_useragent()
                self.session.headers.update({'user-agent': new_ua})
                self.session_unblock.headers.update({'user-agent': new_ua})
                continue

            else:
                return(True)

        with open('errors.txt', 'a') as file:
            file.write(f'None | {self.cookies_str}\n')

        return(False)

    def first_step(self):
        self.session.post('https://api.twitter.com/1.1/jot/client_event.json',
                          data='category=perftown&'
                               'log=[{"description":"rweb:cookiesMetadata:load",'
                               '"product":"rweb",'
                               '"event_value":' + str(int(time())) + str(randint(0, 9)) + '}]',
                          headers={'content-type': 'application/x-www-form-urlencoded'},
                          verify=False)

        self.session.post('https://twitter.com/i/api/1.1/attribution/event.json',
                          json={"event": "open"},
                          headers={'content-type': 'application/json'},
                          verify=False)

        self.session.get('https://twitter.com/i/api/1.1/account/settings.json?'
                         'include_mention_filter=true&'
                         'include_nsfw_user_flag=true&'
                         'include_nsfw_admin_flag=true&'
                         'include_ranked_timeline=true&'
                         'include_alt_text_compose=true&'
                         'ext=ssoConnections&'
                         'include_country_code=true&'
                         'include_ext_dm_nsfw_media_filter=true&'
                         'include_ext_sharing_audiospaces_listening_data_with_followers=true',
                         verify=False)

        self.session.get('https://twitter.com/manifest.json',
                         verify=False)

        self.session.post('https://api.twitter.com/1.1/jot/client_event.json',
                          data='debug=true&'
                               'log=[{"_category_":"client_event",'
                               '"format_version":2,'
                               '"triggered_on":' + str(int(time()))
                               + str(randint(100, 999)) + ',"message":"normal/blue500/darker",'
                               '"items":[],'
                               '"event_namespace":{"page":"app","component":'
                               '"theme","action":"launch","client":"m5"},'
                               '"client_event_sequence_start_timestamp":'
                               + str(int(time())) + str(randint(100, 999)) +
                               ',"client_event_sequence_number":0,'
                               '"client_app_id":"' + str(self.action_refresh) + '"}]',
                          headers={'content-type': 'application/x-www-form-urlencoded'},
                          verify=False)

        self.session.get('https://twitter.com/i/api/2/badge_count/badge_count.json?'
                         'supports_ntab_urt=1',
                         verify=False)

        self.session.post('https://twitter.com/i/api/1.1/branch/init.json',
                          json={},
                          headers={'content-type': 'application/json'},
                          verify=False)

        self.session.get(f'https://twitter.com/i/api/graphql/{self.queryIdforDataSaverMode}'
                         '/DataSaverMode?variables={"device_id":"Windows/Chrome"}',
                         verify=False)

        sequenceStartTimestampMs = int(f'{int(time())}{random_with_N_digits(3)}')
        visibilityPctDwellStartMs = str(int(f'{int(time())}{random_with_N_digits(3)}')
                                        - int(random_with_N_digits(4)))
        visibilityPctDwellEndMs = str(int(visibilityPctDwellStartMs) - randint(0, 100))

        self.session.post('https://twitter.com/i/api/1.1/jot/ces/p2',
                          json={
                              "events": [
                                  {"sequenceStartTimestampMs": sequenceStartTimestampMs,
                                   "sequenceNumber": 0,
                                   "createdAtMs": sequenceStartTimestampMs,
                                   "event":
                                   {"behavioralEvent": {
                                    "v1":
                                    {"context":
                                     {"v1":
                                      {}},
                                     "action":
                                     {"impress":
                                      {"v2":
                                       {"minVisibilityPct": 0,
                                        "minDwellMs": 0,
                                        "visibilityPctDwellStartMs": ""
                                        + visibilityPctDwellStartMs + "",
                                        "visibilityPctDwellEndMs": ""
                                        + visibilityPctDwellEndMs + "",
                                        "count": 1}
                                       }
                                      },
                                        "targetView":
                                        {"v1":
                                         {"viewHierarchy":
                                          [{"statefulView":
                                           {"v1":
                                            {"viewType": "profile",
                                             "viewState":
                                             {"emptyness": {}}
                                             }
                                            }
                                            }]}
                                         }
                                     }
                                    }
                                    }
                                   }],
                              "header": {"createdAtMs": sequenceStartTimestampMs - randint(0, 100),
                                         "retryAttempt": 0}
                          },
                          verify=False)

    def unfreeze_account(self):
        for _ in range(15):
            try:
                r = self.session_unblock.get('https://twitter.com/account/access',
                                             verify=False)

                if '<p class="errorButton">'\
                   '<a href="https://help.twitter.com/using-twitter/twitter-supported-browsers">'\
                        in r.text:
                    raise Wrong_UserAgent('')

                handle_errors(r)

                authenticity_token = BeautifulSoup(r.text, 'lxml')\
                    .find('input', {'name': 'authenticity_token'}).get('value')
                assignment_token = BeautifulSoup(r.text, 'lxml')\
                    .find('input', {'name': 'assignment_token'}).get('value')

                r = self.session_unblock.post('https://twitter.com/account/access',
                                              headers={
                                                  'accept': 'text/html,application/'
                                                            'xhtml+xml,application/'
                                                            'xml;q=0.9,image/avif,image/'
                                                            'webp,image/apng,*/*;'
                                                            'q=0.8,application/'
                                                            'signed-exchange;'
                                                            'v=b3;q=0.9',
                                                  'content-type': 'application/'
                                                                  'x-www-form-urlencoded',
                                                  'origin': 'https://twitter.com',
                                                  'referer': 'https://twitter.com/account/access'},
                                              data=f'authenticity_token={authenticity_token}&'
                                                   f'assignment_token={assignment_token}&'
                                                   f'lang={self.lang}&'
                                                   'flow=',
                                              verify=False)

                handle_errors(r)

                if 'Due to a technical issue, we couldn\'t complete this request. '\
                        'Please try again.' in r.text:
                    raise Wrong_Response('')

            except Exception as error:
                logger.error(f'Ошибка при снятии временной блокировки: {str(error)}')

            except Wrong_Response as error:
                response_formated = str(r.text.replace('\n', ''))
                logger.error(f'Ошибка при снятии временной блокировки: '
                             f'{str(error)}, код ответа: {str(r.status_code)}, '
                             f'ответ: {response_formated}')

            except Wrong_UserAgent:
                new_ua = random_useragent()
                self.session_unblock.headers['user-agent'] = new_ua
                self.session.headers['user-agent'] = new_ua

            else:
                logger.success('Временная блокировка успешно снята')

                return(True)

        return(False)

    def new_inffl_parse(self, write_option):
        while True:
            with open("infl_id.txt", "r") as file1:
                while True:
                    line = file1.readline()
                    id_for_url = line.strip()
                    if not line:
                        break

                    try:
                        user_list = []
                        r = self.session.get('https://mobile.twitter.com/i/api/graphql/dSFUC8Els4daKxSC4NEm9w/Following?variables={"userId":"'+id_for_url+'","count":90,"includePromotedContent":false,"withSuperFollowsUserFields":true,"withDownvotePerspective":false,"withReactionsMetadata":false,"withReactionsPerspective":false,"withSuperFollowsTweetFields":true}&features={"dont_mention_me_view_api_enabled":true,"interactive_text_enabled":true,"responsive_web_uc_gql_enabled":false,"vibe_api_enabled":true,"responsive_web_edit_tweet_api_enabled":false,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":false,"responsive_web_enhance_cards_enabled":false}',verify=False)
                        chto = str(r.text)
                        cursor_pattern = r'TimelineTimelineCursor","value":"(.*?)","cursorType"'
                        nickname_patterrn = r'"screen_name":"(.*?)"'
                        nicknames = findall(nickname_patterrn, chto)
                        first_cursor = findall(cursor_pattern, chto)
                        next_cursor = first_cursor[0]
                        check_cursor = next_cursor.split("|")[0]
                        user_list = user_list + nicknames
                        while check_cursor != "0":
                            r = self.session.get('https://mobile.twitter.com/i/api/graphql/dSFUC8Els4daKxSC4NEm9w/Following?variables={"userId":"'+id_for_url+'","count":90,"cursor":"'+next_cursor+'","includePromotedContent":false,"withSuperFollowsUserFields":true,"withDownvotePerspective":false,"withReactionsMetadata":false,"withReactionsPerspective":false,"withSuperFollowsTweetFields":true}&features={"dont_mention_me_view_api_enabled":true,"interactive_text_enabled":true,"responsive_web_uc_gql_enabled":false,"vibe_api_enabled":true,"responsive_web_edit_tweet_api_enabled":false,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":false,"responsive_web_enhance_cards_enabled":false}',verify=False)
                            chto = str(r.text)
                            nicknames = findall(nickname_patterrn, chto)
                            next_cursor = findall(cursor_pattern, chto)
                            next_cursor = next_cursor[0]
                            check_cursor = next_cursor.split("|")[0]
                            user_list = user_list + nicknames
                        with open('data/'+id_for_url+'.txt', 'w') as file:
                            file.write(str(user_list))

                        handle_errors(r)

                    except:
                        logger.error('Somethings troubles...')

            with open('errors.txt', 'a') as file:
                file.write(f'{self.username} | {self.cookies_str}\n')

            return(False, None)

    def check_newfollows(self, write_option):
        while True:
            with open("infl_id.txt", "r") as file1:
                news = ""
                while True:
                    line = file1.readline()
                    if not line:
                        with open('news.txt', 'a') as file2:
                            file2.write(news)
                        sleep(1800)
                        break
                    lineeee = line.strip()
                    id_for_url = lineeee.split("|")[0]
                    name_for_split = lineeee.split("|")[1]
                    try:
                        user_list = []
                        r = self.session.get('https://mobile.twitter.com/i/api/graphql/dSFUC8Els4daKxSC4NEm9w/Following?variables={"userId":"'+id_for_url+'","count":90,"includePromotedContent":false,"withSuperFollowsUserFields":true,"withDownvotePerspective":false,"withReactionsMetadata":false,"withReactionsPerspective":false,"withSuperFollowsTweetFields":true}&features={"dont_mention_me_view_api_enabled":true,"interactive_text_enabled":true,"responsive_web_uc_gql_enabled":false,"vibe_api_enabled":true,"responsive_web_edit_tweet_api_enabled":false,"standardized_nudges_misinfo":true,"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled":false,"responsive_web_enhance_cards_enabled":false}',verify=False)
                        chto = str(r.text)
                        nickname_patterrn = r'"screen_name":"(.*?)"'
                        nicknames = findall(nickname_patterrn, chto)
                        user_list = user_list + nicknames
                        with open('data/'+id_for_url+'.txt', 'r') as file:
                            data_old = file.read()
                            old_follow = list(data_old.split("', '"))
                            res = [x for x in user_list + old_follow if x not in old_follow]
                            if not res:
                                logger.success(f'{name_for_split} Изменений нет')
                            else:
                                i = 0
                                while i<len(res):
                                    logger.success(f'{name_for_split}  подисался на https://twitter.com/{str(res[i])}')
                                    news = news + name_for_split+" подисался на https://twitter.com/" + str(res[i]) + "\n"
                                    i += 1
                                    with open('data/'+id_for_url+'.txt', 'a') as file3:
                                        new_f = "', '" + str(res[i])
                                        file3.write(new_f)
                        handle_errors(r)

                    except:
                        logger.error('Somethings troubles...')

        with open('errors.txt', 'a') as file:
            file.write(f'{self.username} | {self.cookies_str}\n')

        return(False, None)


def start(current_cookies_str, proxy_str, wallet_address, changed_username):
    app = App(current_cookies_str, proxy_str)
    app_get_values_response = app.get_values()

    if app_get_values_response:
        if user_action == 1:
            get_username_status, current_username = app.new_inffl_parse(True)
        if user_action == 2:
            get_username_status, current_username = app.check_newfollows(True)



def get_usernames(current_cookies_str, proxy_str):
    app = App(current_cookies_str, proxy_str)
    app_get_values_response = app.get_values()

    if app_get_values_response:
        get_username_status, current_username = app.check_newfollows(None)

        if get_username_status:
            return(current_username)

        else:
            return(None)


if __name__ == '__main__':
    clear()
    pool = Pool(threads)

    proxies = [None for _ in range(len(accounts_cookies))]

    wallets_addresses = [None for _ in range(len(accounts_cookies))]
    new_usernames_list = [None for _ in range(len(accounts_cookies))]

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(start, accounts_cookies, proxies, wallets_addresses, new_usernames_list)

    logger.success('Работа успешно завершена')
    print('\nPress Any Key To Exit..')
    getch()
    exit()