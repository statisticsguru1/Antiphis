# lexical features
from math import log
from re import compile
from urllib.parse import urlparse
from socket import gethostbyname
from pyquery import PyQuery
from requests import get
from json import dump, loads
from string import ascii_lowercase
from numpy import array

cache = []

class LexicalURLFeature:
    def __init__(self, url):
        self.description = 'blah'
        self.url = url
        self.urlparse = urlparse(self.url)
        self.host = self.__get_ip()


    def __get_entropy(self, text):
        text = text.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum([p * log(p) / log(2.0) for p in probs])
        return entropy

    def __get_ip(self):
        try:
            ip = self.urlparse.netloc if self.url_host_is_ip() else gethostbyname(self.urlparse.netloc)
            return ip
        except:
            return None

    # extract lexical features
    def url_scheme(self):
        print(self.url)
        print(self.urlparse)
        return self.urlparse.scheme

    def url_length(self):
        return len(self.url)

    def url_path_length(self):
        return len(self.urlparse.path)

    def url_host_length(self):
        return len(self.urlparse.netloc)

    def url_host_is_ip(self):
        host = self.urlparse.netloc
        pattern = compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def url_has_port_in_string(self):
        has_port = self.urlparse.netloc.split(':')
        return len(has_port) > 1 and has_port[-1].isdigit()

    def number_of_digits(self):
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def number_of_parameters(self):
        params = self.urlparse.query
        return 0 if params == '' else len(params.split('&'))

    def number_of_fragments(self):
        frags = self.urlparse.fragment
        return len(frags.split('#')) - 1 if frags == '' else 0

    def is_encoded(self):
        return '%' in self.url.lower()

    def num_encoded_char(self):
        encs = [i for i in self.url if i == '%']
        return len(encs)

    def url_string_entropy(self):
        return self.__get_entropy(self.url)

    def number_of_subdirectories(self):
        d = self.urlparse.path.split('/')
        return len(d)

    def number_of_periods(self):
        periods = [i for i in self.url if i == '.']
        return len(periods)

    def has_client_in_string(self):
        return 'client' in self.url.lower()

    def has_admin_in_string(self):
        return 'admin' in self.url.lower()

    def has_server_in_string(self):
        return 'server' in self.url.lower()

    def has_login_in_string(self):
        return 'login' in self.url.lower()
        
    def get_tld(self):
        return self.urlparse.netloc.split('.')[-1].split(':')[0]
    
    def run(self):
        if self.url not in cache:
            try:
                fv = {
                'host': self.host,
                'tld': self.get_tld(),
                'scheme': self.url_scheme(),
                'url_length': self.url_length(),
                'path_length': self.url_path_length(),
                'host_length': self.url_host_length(),
                'host_is_ip': self.url_host_is_ip(),
                'has_port_in_string': self.url_has_port_in_string(),
                'num_digits': self.number_of_digits(),
                'parameters': self.number_of_parameters(),
                'fragments': self.number_of_fragments(),
                'is_encoded': self.is_encoded(),
                'string_entropy': self.url_string_entropy(),
                'subdirectories': self.number_of_subdirectories(),
                'periods': self.number_of_periods(),
                'has_client': self.has_client_in_string(),
                'has_login': self.has_login_in_string(),
                'has_admin': self.has_admin_in_string(),
                'has_server': self.has_server_in_string(),
                'num_encoded_chars': self.num_encoded_char(),
                'url': self.url
                }
                return fv
            except:
                pass
        else:
            print('seen url')


# content features
from urllib.parse import urlparse
from pyquery import PyQuery
from requests import get
from socket import gethostbyname
from numpy import array, log
from string import punctuation
from json import dump, loads
from re import compile

# get valid tags and suspicious function
def get_valid_html_tags():
    pq = PyQuery(get('https://htmldog.com/references/html/tags/').content)
    items = pq('.longlist.acodeblock ul li a code')
    tags = [i.text().lower() for i in items.items()]
    return tags

def get_suspicious_functions(url='https://gist.githubusercontent.com/eneyi/5c0b33129bcbfa366eb9fe79e96c1996/raw/96217aa7ea6698b17151f866f891ba701cbd7537/mal_script_functions.txt'):
    content = get(url).text.split('\n')
    return content

class ContentFeatures:
    def __init__(self, url,vd,sf):
        self.url = url
        self.urlparse = urlparse(self.url)
        self.html = self.__get_html()
        self.pq = self.__get_pq()
        self.scripts = self.__get_scripts()
        self.valid_tags = vd
        self.suspicious_functions = sf
        self.host = self.__get_ip()

    def __get_ip(self):
        try:
            ip = self.urlparse.netloc if self.url_host_is_ip() else gethostbyname(self.urlparse.netloc)
            return ip
        except:
            return None


    def url_host_is_ip(self):
        host = self.urlparse.netloc
        pattern = compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def __get_html(self):
        try:
            html = get(self.url, timeout=5)
            html = html.text if html else None
        except:
            html = None
        return html

    def __get_pq(self):
        try:
            pq = PyQuery(self.html) if self.html else None
            return pq
        except:
            return None


    def __get_scripts(self):
        scripts = self.pq('script') if self.pq else None
        return scripts

    def __get_entropy(self, text):
        text = text.lower()
        probs = [text.count(c) / len(text) for c in set(text)]
        return -sum([p * log(p) / log(2.0) for p in probs])

    # extract content-based features
    def url_page_entropy(self):
        return self.__get_entropy(self.html)

    def number_of_script_tags(self):
        return len(self.scripts) if self.scripts else None

    def script_to_body_ratio(self):
        if self.scripts:
            scripts = self.scripts.text()
            return len(scripts)/self.length_of_html()
        else:
            return None

    def length_of_html(self):
        return len(self.html)

    def number_of_page_tokens(self):
        html_tokens = len(self.html.lower().split()) if self.html else None
        return html_tokens

    def number_of_sentences(self):
        html_sentences = len(self.html.split('.')) if self.html else None
        return html_sentences

    def number_of_punctuations(self):
        excepts = ['<', '>', '/']
        matches = [i for i in self.html if i in punctuation and i not in excepts]
        return len(matches)

    def number_of_distinct_tokens(self):
        html_tokens = [i.strip() for i in self.html.lower().split()]
        return len(set(html_tokens))

    def number_of_capitalizations(self):
        uppercases = [i for i in self.html if i.isupper()]
        return len(uppercases)

    def average_number_of_tokens_in_sentence(self):
        html_sentences = self.html.split('.')
        sen_lens = [len(i.split()) for i in html_sentences]
        return sum(sen_lens)/len(sen_lens)

    def number_of_html_tags(self):
        return len(self.pq('*')) if self.pq else None

    def number_of_hidden_tags(self):
        hidden1, hidden2 = self.pq('.hidden'), self.pq('#hidden')
        hidden3, hidden4 = self.pq('*[visibility="none"]'), self.pq('*[display="none"]')
        hidden = hidden1 + hidden2 + hidden3 + hidden4
        return len(hidden)

    def number_iframes(self):
        iframes = self.pq('iframe') + self.pq('frame')
        return len(iframes)

    def number_objects(self):
        objects = self.pq('object')
        return len(objects)

    def number_embeds(self):
        objects = self.pq('embed')
        return len(objects)

    def number_of_hyperlinks(self):
        hyperlinks = self.pq('a')
        return len(hyperlinks)

    def number_of_whitespace(self):
        whitespaces = [i for i in self.html if i == ' ']
        return len(whitespaces)

    def number_of_included_elements(self):
        toi = self.pq('script') + self.pq('iframe') + self.pq('frame') + self.pq('embed') + self.pq('form') + self.pq('object')
        toi = [tag.attr('src') for tag in toi.items()]
        return len([i for i in toi if i])

    def number_of_suspicious_elements(self):
        all_tags = [i.tag for i in self.pq('*')]
        suspicious = [i for i in all_tags if i not in self.valid_tags]
        return len(suspicious)

    def number_of_double_documents(self):
        tags = self.pq('html') + self.pq('body') + self.pq('title')
        return len(tags) - 3

    def number_of_eval_functions(self):
        scripts = self.pq('script')
        scripts = ['eval' in script.text().lower() for script in scripts.items()]
        return sum(scripts)

    def average_script_length(self):
        scripts = self.pq('script')
        scripts = [len(script.text()) for script in scripts.items()]
        l = len(scripts)
        if l > 0:
            return sum(scripts) / l
        else:
            return 0

    def average_script_entropy(self):
        scripts = self.pq('script')
        scripts = [self.__get_entropy(script.text()) for script in scripts.items()]
        l = len(scripts)
        if l > 0:
            return sum(scripts) / l
        else:
            return 0

    def number_of_suspicious_functions(self):
        script_content = self.pq('script').text()
        susf = [1 if i in script_content else 0 for i in self.suspicious_functions]
        return sum(susf)
    
    def run(self):
        if self.url not in cache:
            try:
                if self.html and self.pq:
                    data = {}
                    data['host'] = self.host
                    data['page_entropy'] = self.url_page_entropy()
                    data['num_script_tags'] = self.number_of_script_tags()
                    data['script_to_body_ratio'] = self.script_to_body_ratio()
                    data['html_length'] = self.length_of_html()
                    data['page_tokens'] = self.number_of_page_tokens()
                    data['num_sentences'] = self.number_of_sentences()
                    data['num_punctuations'] = self.number_of_punctuations()
                    data['distinct_tokens'] = self.number_of_distinct_tokens()
                    data['capitalizations'] = self.number_of_capitalizations()
                    data['avg_tokens_per_sentence'] = self.average_number_of_tokens_in_sentence()
                    data['num_html_tags'] = self.number_of_html_tags()
                    data['num_hidden_tags'] = self.number_of_hidden_tags()
                    data['num_iframes'] = self.number_iframes()
                    data['num_embeds'] = self.number_embeds()
                    data['num_objects'] = self.number_objects()
                    data['hyperlinks'] = self.number_of_hyperlinks()
                    data['num_whitespaces'] = self.number_of_whitespace()
                    data['num_included_elemets'] = self.number_of_included_elements()
                    data['num_double_documents'] = self.number_of_double_documents()
                    data['num_suspicious_elements'] = self.number_of_suspicious_elements()
                    data['num_eval_functions'] = self.number_of_eval_functions()
                    data['avg_script_length'] = self.average_script_length()
                    data['avg_script_entropy'] = self.average_script_entropy()
                    data['num_suspicious_functions'] = self.number_of_suspicious_functions()
                    data['url'] = self.url
                    return data
                else:
                    pass
            except:
                print('OOPS ERROR')
        else:
            print('seen url')


# host features
import whois
#from waybackpy import Cdx
from waybackpy import WaybackMachineCDXServerAPI as Cdx
from socket import gethostbyname
from shodan import Shodan
from requests import get
from urllib.parse import urlparse
from datetime import datetime
from re import compile
from json import dump, loads
from time import sleep

class HostFeatures:
    def __init__(self, url):
        self.url = url
        self.urlparse = urlparse(self.url)
        self.host = self.__get_ip()
        self.now = datetime.now()
        self.init_sub_params = self.initialise_sub_parameters()

    def initialise_sub_parameters(self):
        if self.host not in cache:
            self.whois = self.__get__whois_dict()
            self.shodan = self.__get_shodan_dict()
            self.snapshots = self.__get_site_snapshots()
            return True
        else:
            return False

    def __get_ip(self):
        try:
            ip = self.urlparse.netloc if self.url_host_is_ip() else gethostbyname(self.urlparse.netloc)
            return ip
        except:
            return None

    def __get__whois_dict(self):
        try:
            whois_dict = whois(self.host)
            return whois_dict
        except:
            return {}

    def __get_shodan_dict(self):
        api = Shodan('W6cy1PGcje0jJwKDBTgrqWSZioRpRmzg')
        try:
            host = api.host(self.host)
            return host
        except:
            return {}

    def __parse__before__date(self, date_string):
        month_year = date_string.split()[-1]
        d = '01-{}'.format(month_year)
        d = datetime.strptime(d, '%d-%b-%Y')
        return d

    def __parse_whois_date(self, date_key):
        cdate = self.whois.get(date_key, None)
        if cdate:
            if isinstance(cdate, str) and 'before' in cdate:
                d = self.__parse__before__date(cdate)
            elif isinstance(cdate, list):
                d = cdate[0]
            else:
                d = cdate
        return d if cdate else cdate

    def __get_site_snapshots(self):
        try:
            snapshots = Cdx(self.urlparse.netloc).snapshots()
            snapshots = [snapshot.datetime_timestamp for snapshot in snapshots]
            return snapshots
        except:
            return []

    def url_host_is_ip(self):
        host = self.urlparse.netloc
        pattern = compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def number_of_subdomains(self):
        ln1 = self.whois.get('nets', None)
        ln2 = self.shodan.get('domains', None)
        ln = ln1 or ln2
        return len(ln) if ln else None

    def url_creation_date(self):
        d = self.__parse_whois_date('creation_date')
        return d

    def url_expiration_date(self):
        d = self.__parse_whois_date('expiration_date')
        return d

    def url_last_updated(self):
        d = self.__parse_whois_date('updated_date')
        return d

    def url_age(self):
        try:
            days = (self.now - self.url_creation_date()).days
        except:
            days = None
        return days

    def url_intended_life_span(self):
        try:
            lifespan = (self.url_expiration_date() - self.url_creation_date()).days
        except:
            lifespan = None
        return lifespan

    def url_life_remaining(self):
        try:
            rem = (self.url_expiration_date() - self.now).days
        except:
            rem = None
        return rem

    def url_registrar(self):
        return self.whois.get('registrar', None)

    def url_registration_country(self):
        c = self.whois.get('country', None)
        return c

    def url_host_country(self):
        c = self.shodan.get('country_name', None)
        return c

    def url_open_ports(self):
        ports = self.shodan.get('ports', '')
        return ports if ports != '' else None

    def url_num_open_ports(self):
        ports = self.url_open_ports()
        lp = len(ports) if ports else 0
        return lp

    def url_is_live(self):
        url = '{}://{}'.format(self.urlparse.scheme, self.urlparse.netloc)
        try:
            return get(url).status_code == 200
        except:
            return False

    def url_isp(self):
        return self.shodan.get('isp', '')

    def url_connection_speed(self):
        url = '{}://{}'.format(self.urlparse.scheme, self.urlparse.netloc)
        if self.url_is_live():
            return get(url).elapsed.total_seconds()
        else:
            return None

    def first_seen(self):
        try:
            fs = self.snapshots[0]
            return fs
        except:
            return datetime.now()

    def get_os(self):
        oss = self.shodan.get('os', None)
        return oss

    def last_seen(self):
        try:
            ls = self.snapshots[-1]
            return ls
        except:
            return datetime.now()

    def days_since_last_seen(self):
        dsls = (self.now - self.last_seen()).days
        return dsls

    def days_since_first_seen(self):
        dsfs = (self.now - self.first_seen()).days
        return dsfs

    def average_update_frequency(self):
        snapshots = self.snapshots
        diffs = [(t-s).days for s, t in zip(snapshots, snapshots[1:])]
        l = len(diffs)
        if l > 0:
            return sum(diffs)/l
        else:
            return 0

    def number_of_updates(self):
        return len(self.snapshots)

    def ttl_from_registration(self):
        earliest_date_seen = self.first_seen()
        try:
            ttl_from_reg = (earliest_date_seen - self.url_creation_date()).days
        except:
            ttl_from_reg = None
        return ttl_from_reg
    def run(self):
        if self.init_sub_params:
            try:
                fv={
                   "host": self.host,
                   "num_subdomains": self.number_of_subdomains(),
                   "registration_date": str(self.url_creation_date()),
                   "expiration_date": str(self.url_expiration_date()),
                   "last_updates_dates": str(self.url_last_updated()),
                   "age": self.url_age(),
                   "intended_life_span": self.url_intended_life_span(),
                   "life_remaining": self.url_life_remaining(),
                   "registrar": self.url_registrar(),
                   "reg_country": self.url_registration_country(),
                   "host_country": self.url_host_country(),
                   "open_ports": self.url_open_ports(),
                   "num_open_ports": self.url_num_open_ports(),
                   "is_live": self.url_is_live(),
                   "isp": self.url_isp(),
                   "connection_speed": self.url_connection_speed(),
                   "first_seen": str(self.first_seen()),
                   "last_seen": str(self.last_seen()),
                   "days_since_last_seen": self.days_since_last_seen(),
                   "days_since_first_seen": self.days_since_first_seen(),
                   "avg_update_days": self.average_update_frequency(),
                   "total_updates": self.number_of_updates(),
                   "ttl": self.ttl_from_registration()
                }
                return fv
            except:
                print('OOPS')
                pass
        else:
            print('Seen Host')
            return None 

# function to print

class DictionaryPrinter:
    def __init__(self, my_dict,num_columns=1):
        self.my_dict = my_dict
        self.num_columns=num_columns
        
    def print_dict(self):
        items = self.my_dict.items()
        num_columns=self.num_columns
        num_items = len(items)
        num_rows = num_items // num_columns + (num_items % num_columns > 0)
        items = iter(items)
        for row in range(num_rows):
            row_items = [next(items, None) for _ in range(num_columns)]
            row_str = "    ".join("{:<25} {}".format(key + ":", value) for key, value in row_items if key is not None)
            print(row_str)
