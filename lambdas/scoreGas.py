import json
import boto3
import re
import datetime
from collections import defaultdict


s3_client = boto3.client("s3")


# utils
def flatten(list_of_lists):
    if len(list_of_lists) == 0:
        return list_of_lists
    if isinstance(list_of_lists[0], list):
        return flatten(list_of_lists[0]) + flatten(list_of_lists[1:])
    return list_of_lists[:1] + flatten(list_of_lists[1:])


class EventObj:
    def __init__(self, event, job_id, job_tag, bucket, temp_folder):
        self.event = event
        self.job_id = job_id
        self.job_tag = job_tag
        self.bucket = bucket
        self.temp_folder = temp_folder

    def __str__(self):
        return f"Event: Job ID: {self.job_id} - Job Tag: {self.job_tag}"


class PDF:
    def __init__(self, textract, tables, key_values):
        self.tables = tables
        self.textract = textract
        self.key_values = key_values
        self.keys = None
        self.values = None
        self.entity_list = []
        self.clean_key_values = None
        self.date_issued = None
        self.dates = []
        self.received_data = None
        self.postcodes = []
        self.addresses = []
        self.address_received = None
        self.table_text = None
        self.split_tables = []
        self.valid_date = None
        self.valid_serial = None

    def get_tables(self, object_key, received_event):
        temp_folder = received_event.temp_folder
        job_tag = received_event.job_tag
        bucket = received_event.bucket
        table_key = f"{temp_folder}/{job_tag}/tables.csv"
        table_content = s3_client.get_object(Bucket=bucket, Key=table_key)[
            "Body"
        ].read()
        self.tables = table_content

    def get_key_values(self, received_event):
        temp_folder = received_event.temp_folder
        job_tag = received_event.job_tag
        bucket = received_event.bucket
        object_key = f"{temp_folder}/{job_tag}/key_value_list.json"
        file_content = s3_client.get_object(Bucket=bucket, Key=object_key)[
            "Body"
        ].read()
        entities = json.loads(file_content)
        entity_list = []
        # get entities
        for k, v in entities.items():
            k = k.lower().rstrip(": ")
            if len(v) > 1:
                for value in v:
                    new_entity = Entity(k, value)
                    entity_list.append(new_entity)
            else:
                new_entity = Entity(k, v[0])
                entity_list.append(new_entity)
        self.entity_list = entity_list
        self.key_values = entities
        self.clean_key_values = {
            k.rstrip(": ").lower(): v[0].rstrip().lower() for k, v in entities.items()
        }
        keys = [x.lower().rstrip(": ") for x in list(self.clean_key_values.keys())]
        self.keys = keys
        values = [x.lower() for x in list(self.clean_key_values.values())]
        self.values = values

    def get_postcodes(self):
        kv_postcodes = []

        keys = self.keys
        values = self.values
        text = keys + values

        # key value postcodes
        postcode_regex = re.compile("[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}")
        for item in text:
            kv_postcodes.append(postcode_regex.findall(item.upper()))

        tables_postcodes = []
        # table postcodes
        text = self.tables.decode("utf-8")
        tables_postcodes = postcode_regex.findall(text.upper())

        postcodes = kv_postcodes + tables_postcodes
        postcodes = [x for x in postcodes if x]

        postcodes = list(set(flatten(postcodes)))

        self.postcodes = postcodes

    def get_addresses(self):
        postcodes = self.postcodes
        entities = self.key_values
        clean_entities = {
            k.rstrip(": ").lower(): v[0].rstrip().lower() for k, v in entities.items()
        }
        addresses = []
        address = None

        # key value addresseses
        for postcode in postcodes:
            postcode = postcode.lower()
            for element in clean_entities.keys():
                address = []
                element = element.lower()
                if postcode in element:
                    address = element
                    addresses.append(address)
                    print(address)
            for element in clean_entities.values():
                address = []
                element = element.lower()
                if postcode in element:
                    address = element
                    addresses.append(address)
                    print(address)

        addresses = [x for x in addresses if x]
        addresses = list(set(flatten(addresses)))
        self.addresses = addresses

    def get_address_data(self):
        for address in self.addresses:
            print(address)

    def get_dates(self):
        keys = self.keys
        values = self.values
        text = keys + values
        split_tables = self.split_tables
        full_text = flatten(split_tables) + text
        date_pattern = "(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})"
        date_re = re.compile(date_pattern)

        date_list = []
        for item in full_text:
            if bool(date_re.findall(item)) == True:
                print(True)
                date_list.append(date_re.findall(item))

        date_list = flatten(date_list)
        self.dates = date_list

    def get_features(self, features_set):
        keys = self.keys
        values = self.values
        text = keys + values

        kv_features = []
        table_features = []
        table_text = self.tables.decode("utf-8").lower()

        # key value feature match
        for features in features_set:
            for feature in features:
                feature = feature.lower()
                # feature regex
                feature_regex = re.compile(feature)
                for item in text:
                    if bool(feature_regex.match(item)) == True:
                        kv_features.append(feature)

        kv_features = list(set(flatten(kv_features)))
        kv_features = [x for x in kv_features if x]

        # table feature match
        table_text = table_text.replace("\n", "")
        table_text = table_text.replace(",", "")
        table_text = table_text.replace(",", "")

        self.table_text = table_text

        split_tables = [l.split("table: ") for l in table_text.split("table: ")]
        split_tables.remove([""])

        self.split_tables = split_tables

        table_features = []

        for features in features_set:
            for feature in features:
                feature = feature.lower()
                # table feature match
                for table in split_tables:
                    table = table[0].lower()
                    if bool(feature_regex.findall(table)) == True:
                        table_features.append(feature)

        features = kv_features + table_features
        features = [x for x in features if x]
        features = list(set(flatten(features)))

        self.features = list(set(kv_features + table_features))

    def calculate_feature_score(self):
        keys = self.keys
        values = self.values
        text = keys + values
        tables = self.table_text
        split_tables = self.split_tables
        full_text = flatten(split_tables) + text

        score = 0
        contributing_score = 0
        total_possible_score = 0

        # score calculation, calculate score after by removing found values
        simple_search = []
        contributing_search = []

        for item in full_text:
            # negative search
            if "building regulation" in item:
                score = 0
                return score
            # simple search
            if "gas safety record" in item:
                simple_search.append("gas safety record")
            elif "gas safety" in item or "gas safe" in item or "safety record" in item:
                simple_search.append("gas safe")
            if "gas safety (installation and use) regulations" in item:
                simple_search.append("gas safety (installation and use) regulations")
            elif "installation and use" in item:
                simple_search.append("installation and use")

            # contributing scores
            if "chimney" or "flue" in item:
                contributing_search.append("chimney")
            if "tightness test" in item:
                contributing_search.append("tightness")
            if "combustion analyser" in item:
                contributing_search.append("combustion")
            if "operating pressure" in item:
                contributing_search.append("operating")
            if "appliance service" in item:
                contributing_search.append("appliance")

        # calculate simple search score
        simple_search = list(set(simple_search))
        simple_search_score = 0

        contributing_search = list(set(contributing_search))
        contributing_score = 0

        print("Simple", simple_search)
        print("Contributing", contributing_search)

        # simple calc
        for item in simple_search:
            if "gas safe" in item:
                simple_search.remove("gas safe")
                simple_search_score += 50
            elif "gas safety" in item:
                simple_search.remove("gas safety")
                simple_search_score += 25
            elif "safety record" in item:
                simple_search_score += 25
            total_possible_score += 50

            if "gas safety (installation and use) regulations" in item:
                simple_search.remove("gas safety (installation and use) regulations")
                simple_search_score += 50
            elif "installation and use" in item:
                simple_search.remove("installation and use")
                simple_search_score += 25
            total_possible_score += 50

        if len(contributing_search) == 1:
            contributing_score = 10
        elif len(contributing_search) == 2:
            contributing_score = 25
        elif len(contributing_search) >= 3:
            contributing_score = 50
        else:
            contributing_score = 0
        total_possible_score += 50

        total_score = simple_search_score + contributing_score
        overall = total_score / total_possible_score * 100

        self.feature_score = {
            "total": total_score,
            "max": total_possible_score,
            "overall": overall,
        }

        print("SCORE", self.feature_score)

    def calculate_address_score(self):
        keys = self.keys
        values = self.values
        text = keys + values
        tables = self.table_text
        split_tables = self.split_tables
        full_text = flatten(split_tables) + text

        addresses = self.addresses
        address_received = self.address_received
        address_score_list = []
        address_type = None

        if len(self.addresses) == 1:
            address_type = "single"
            print("Single addresses found")
        else:
            address_type = "multiple"
            print("Multiple addresses found")
        for address in addresses:
            address_score = 0
            check = None
            print("Address check:", address, address_received)
            if address_received.line5 in address:
                print("FOUND POSTCODE")
                address_score += 60
            if address_received.line2 in address:
                print("FOUND TOWN")
                address_score += 20
            if address_received.line1 in address:
                print("FOUND FIRST LINE")
                address_score += 60
            address_score_list.append({"address": address, "score": address_score})
        self.address_score = address_score_list

    def check_date(self):
        for date in self.dates:
            date = "".join(date)
            date = datetime.datetime.strptime(date, "%d%m%Y").date()
            if date - self.date_issued < datetime.timedelta(days=365):
                valid_date = True
                break

        self.valid_date = valid_date

    def check_serial(self):
        keys = self.keys
        values = self.values
        text = keys + values
        split_tables = self.split_tables
        full_text = flatten(split_tables) + text
        serial_pattern = self.serial
        serial_regex = re.compile(serial_pattern)

        valid_serial = False
        for item in full_text:
            if bool(serial_regex.findall(item)) == True:
                valid_serial = True
                break

        self.valid_serial = valid_serial


class Entity:
    """
    Key Value returned from Textract API
    """

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __str__(self):
        return f"Entity: {self.key}:{self.value}"

    def postcode(self):
        postcode_regex = re.compile("[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}")
        if bool(postcode_regex.match(self.value.upper())) == True:
            self.postcode = self.value.lower().rstrip(" ")
            return True
        return False


class Address:
    """
    Addresses should all be in lowercase
    Use OS Places API
    """

    def __init__(self, first, second, town, county, postcode, date, serial):
        self.line1 = first
        self.line2 = second
        self.line3 = town
        self.line4 = county
        self.line5 = postcode
        self.date = date
        self.serial = serial
        # check what format address is in then create with lowered text

    def __str__(self):
        return f"Address: {self.line1} {self.line2} {self.line3} {self.line4} {self.line5} {self.date} {self.serial}"

    def calculate_score(self, features):
        "Score parsed address given features to check"
        pass

    def find_address_from_postcode(self, postcode):
        "Find address within tables.csv or key_value.json from a postcode"
        pass

    def valid(self, address_received):
        "Check address is valid for the provided document"
        pass


class Table:
    """
    Tables returned by textract are stored in seperate files
    """

    def __init__(self, rows):
        self.rows = rows
        self.postcodes = []

    def calculate_table_count(self):
        "return count of tables parsed from textract"
        pass

    def find_postcodes(self):
        "find all postcodes within tables.csv"
        postcode_regex = "[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}"
        for row in self.rows:
            if re.findall(postcode_regex, row):
                self.postcodes.append(re.findall(postcode_regex, row))
        return self.postcodes


class KeyValue:
    """
    Entities parsed from textract in key : value format
    """

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __str__(self):
        return f"{self.key} - {self.value}"

    def postcode(self):
        "check if key_value parsed from textract is a postcode"
        postcode_regex = "[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}"
        if re.findall(postcode_regex, self.key):
            self.postcode = self.key
            return self.key.lower()
        if re.findall(postcode_regex, self.value):
            self.postcode = self.value
            return self.value.lower()

    def address(self):
        "check if key_value parsed from textract is a address by searching entity in OS Places API"
        pass


def lambda_handler(event, context):
    """

    Get tables
    Get key values
    score table features
    score address features
    return features found / not found
    return score

    """
    print("Score Gas Certificates")

    # INPUTS
    job_id = event["Payload"]["job_id"]
    job_tag = event["Payload"]["job_tag"]
    bucket = event["Payload"]["bucket"]
    temp_folder = event["Payload"]["folder"]
    entity_list = []
    table = ""

    address_received = {
        "line1": "flat 8",
        "line2": "60 sherwood park road",
        "line3": "sutton",
        "line4": "surrey",
        "line5": "sm1 2sg",
        "date": "12/06/2020",
        "serial": "4516",
    }

    address_received = Address(
        address_received["line1"],
        address_received["line2"],
        address_received["line3"],
        address_received["line4"],
        address_received["line5"],
        address_received["date"],
        address_received["serial"],
    )

    received_event = EventObj(event, job_id, job_tag, bucket, temp_folder)

    # get table data
    table_key = f"{temp_folder}/{job_tag}/tables.csv"
    table_content = s3_client.get_object(Bucket=bucket, Key=table_key)["Body"].read()

    # get key values data
    object_key = f"{temp_folder}/{job_tag}/key_value_list.json"
    file_content = s3_client.get_object(Bucket=bucket, Key=object_key)["Body"].read()
    print(json.loads(file_content))
    entities = json.loads(file_content)

    # get all textract data
    textract_data = None

    document = PDF(textract_data, table_content, entities)

    document.date_issued = None

    document.get_key_values(received_event)

    # postcodes
    print("Getting postcodes")
    document.get_postcodes()
    print(document.postcodes)

    # addresses
    print("Getting addresses")
    document.get_addresses()
    print(document.addresses)

    # address data
    print("Getting address data")
    document.get_address_data()
    print(document.addresses)

    # dates
    print("Getting document dates")
    document.get_dates()
    print(document.dates)

    # features
    print("Getting features")
    with open("features_GAS.json") as file:
        data = json.load(file)
        document.get_features(data)
    print(document.features)

    # feature score
    print("Calculating feature score")
    document.calculate_feature_score()

    # address score
    print("Calculating address score")
    document.address_received = address_received
    document.calculate_address_score()
    print(document.address_score)

    # date validation
    print("Checking date is valid")
    document.date_issued = "12/06/2020"
    document.date_issued = datetime.datetime.strptime(
        document.date_issued, "%d/%m/%Y"
    ).date()
    document.check_date()
    print(document.valid_date)

    # serial validation
    print("Checking serial is found")
    document.serial = address_received.serial
    document.check_serial()
    print(document.valid_serial)

    output = {
        "statusCode": 200,
        "features": document.features,
        "postcodes": document.postcodes,
        "addresses": document.addresses,
        "feature_score": document.feature_score,
        "address_score": document.address_score,
        "dates": document.dates,
        "valid_date": document.valid_date,
        "valid_serial": document.valid_serial,
    }
    return output
