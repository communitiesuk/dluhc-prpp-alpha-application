import json
import boto3
import re


s3_client = boto3.client("s3")


class event_obj:
    def __init__(self, event, job_id, job_tag, bucket, temp_folder):
        self.event = event
        self.job_id = job_id
        self.job_tag = job_tag
        self.bucket = bucket
        self.temp_folder = temp_folder

    def __str__(self):
        return f"Event: Job ID: {self.job_id} - Job Tag: {self.job_tag}"


class pdf:
    def __init__(self, tables, key_values):
        self.tables = tables
        self.key_values = key_values


class entity:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return f"Entity: {self.text}"

    def lower(self):
        return self.lower()

    def upper(self):
        return self.upper()

    def score_entity(self):
        pass


class address:
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

    def score_address(self):
        pass

    def find_matching_addresses(self):
        pass

    def find_address_from_postcode(self):
        pass


class table:
    def __init__(self, rows):
        self.rows = rows
        self.postcodes = []

    def calculate_table_count(self):
        for row in self.rows:
            print(row)

    def find_postcodes(self):
        postcode_regex = "[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}"
        for row in self.rows:
            if re.findall(postcode_regex, row):
                self.postcodes.append(re.findall(postcode_regex, row))
        return self.postcodes


class key_value:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __str__(self):
        return f"{self.key} - {self.value}"

    def postcode(self):
        postcode_regex = "[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}"
        if re.findall(postcode_regex, self.key):
            self.postcode = self.key
            return self.key.lower()
        if re.findall(postcode_regex, self.value):
            self.postcode = self.value
            return self.value.lower()



def score_features(keys, values):
    text = keys + values
    print("Text", text)

    score = 0
    contributing_score = 0

    # score calculation, calculate score after by removing found values
    simple_search = []
    contributing_search = []

    for item in text:
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

        if "gas safety (installation and use) regulations" in item:
            simple_search.remove("gas safety (installation and use) regulations")
            simple_search_score += 50
        elif "installation and use" in item:
            simple_search.remove("installation and use")
            simple_search_score += 25

    if len(contributing_search) == 1:
        contributing_score = 10
    elif len(contributing_search) == 2:
        contributing_score = 25
    elif len(contributing_search) >= 3:
        contributing_score = 50
    else:
        contributing_score = 0

    total_score = simple_search_score + contributing_score
    total_possible_score = 150
    overall = total_score / total_possible_score * 100

    score = {"total": total_score, "max": total_possible_score, "overall": overall}

    print("SCORE", score)

    return score


def calculate_confidence_score(search_arr: list = None, keys=None, values=None):
    # keys_found = [element for element in search_arr if element in keys and not None]
    # values_found = [element for element in search_arr if element in values and not None]
    keys_found = []
    values_found = []
    for element in search_arr:
        try:
            if element in keys and element != None:
                keys_found.append(element)
            if element in values and element != None:
                values_found.append(element)
        except Exception as e:
            print("Cannot compare value:", e)
    total = len(search_arr) * 2
    try:
        keys_found.remove("")
    except:
        print("No empty strings found")
    try:
        values_found.remove("")
    except:
        print("No empty strings found")

    matched_count = len(keys_found) + len(values_found)
    calcuated_count = matched_count / total
    score = score_features(keys, values)
    total_possible_score = 0

    return {
        "keys_found": keys_found,
        "values_found": values_found,
        "score": score,
        "total_possible_score": len(search_arr) * 2,
    }


def find_features(features: list = None, entities=None):
    """
    Takes in a list of features and returns if a match is found with the entities returned from Textract

    Features should be provided in a list.
    features_list = ["Landlord Home Owner Gas Safety Record", "Landlord Gas Safety Record"]

    Entities should be provided in key, value dict
    {'Signature: ': ['ppl '], 'Engineer name: ': ['William Shakespeare '], 'Gas safe card ID: ': ['4087820 ']}

    """

    key_matches = False
    values_matches = False

    print("features", features)
    print("entities", entities)

    keys = [x.lower().rstrip(": ") for x in list(entities.keys())]
    values = [x.lower() for x in list(entities.values())]
    # values = [item[0].lower().rstrip() for item in values_lists]

    search_arr = [feature.lower() for feature in features]

    # key matches
    if any(x in search_arr for x in keys):
        key_matches = True

    # value matches
    if any(x in search_arr for x in values):
        values_matches = True

    if key_matches or values_matches:
        score = calculate_confidence_score(search_arr, keys, values)
        return score
    return None


def evaluate_check(check, entities):
    for item in entity:
        if check(entity):
            return True
        return False
    pass


def find_address_from_postcode(entities, postcode):
    address = None
    for element in entities:
        if postcode in element:
            address = element
            return address
    return None


def find_postcodes(clean_entities):
    postcodes = []
    for element in clean_entities:
        element = element.upper()
        postcode = re.findall(
            "[A-Z]{1,2}[0-9][A-Z0-9]? [0-9][ABD-HJLNP-UW-Z]{2}", element
        )
        postcodes.append(postcode)
    found_postcodes = list(filter(None, postcodes))
    print(found_postcodes)
    return found_postcodes


def validate_address(address_parsed, received_address):
    address_score = 0
    if received_address["line2"] in address_parsed:
        print("FOUND TOWN")
        address_score += 20
    if received_address["line1"] in address_parsed:
        print("FOUND FIRST LINE")
        address_score += 60
    return address_score


def format_postcode_list(postcodes):
    print(postcodes)
    if type(postcodes) == list and type(postcodes[0]) == list:
        postcodes = ["".join(x).lower() for x in postcodes]
    if type(postcodes[0]) == list:
        postcodes = postcodes[0].lower()
    return postcodes


def parse_address_from_postcode(entities, postcodes, received_address):
    address_list = []
    postcodes = format_postcode_list(postcodes)

    for postcode in postcodes:
        parsed_address = find_address_from_postcode(entities, postcode)
        address_list.append(parsed_address)
    print("ADDRESSES FOUND", address_list)
    return address_list


def score_address(entities, received_address):
    address_list = []
    postcodes = []
    address_score = 0
    parsed_address = None

    # create search array
    keys = [x.lower().rstrip(": ") for x in list(entities.keys())]
    values = [item[0].lower().rstrip(": ") for item in list(entities.values())]
    values.remove("")
    search_entities = keys + values

    # find postcodes
    postcodes = find_postcodes(search_entities)
    # find addresses
    parsed_address = parse_address_from_postcode(
        search_entities, postcodes, received_address
    )

    print("Parsed address", parsed_address)

    # score addresses
    if parsed_address:
        for address in parsed_address:
            address_score = validate_address(address, received_address)
            print("ADDRESS SCORE", address, address_score)
    # find match
    return address_score


def lambda_handler(event, context):
    print("Event", event)

    job_id = event["Payload"]["job_id"]
    job_tag = event["Payload"]["job_tag"]
    bucket = event["Payload"]["bucket"]
    temp_folder = event["Payload"]["folder"]
    key_value_list = ""
    table = ""

    received_event = event_obj(event, job_id, job_tag, bucket, temp_folder)
    print(received_event)

    object_key = f"{temp_folder}/{job_tag}/key_value_list.json"
    file_content = s3_client.get_object(Bucket=bucket, Key=object_key)["Body"].read()
    print(json.loads(file_content))
    entities = json.loads(file_content)
    clean_entities = {
        k.rstrip(": ").lower(): v[0].rstrip().lower() for k, v in entities.items()
    }

    table_key = f"{temp_folder}/{job_tag}/tables.csv"
    table_content = s3_client.get_object(Bucket=bucket, Key=table_key)["Body"].read()

    print(table_content)

    parsed_pdf = pdf(table_content, clean_entities)

    print(parsed_pdf)

    # features list should be provided via json uploaded to s3 / edited by API Request for future

    features_list_1 = [
        "Landlord Home Owner Gas Safety Record",
        "Landlord Gas Safety Record",
        "Homeowner Gas Safety Record",
        "Landlord Safety Record",
        "Gas Safety Record",
        "Domestic Landlord Gas Safety Record",
        "Domestic Homeowner Gas Safety Record",
        "Gas Safety Record",
        "Gas safe ID",
        "Gas Safe Reg No",
        "Gas Safe",
        "Gas Safe Card Id",
    ]
    features_list_2 = [
        "ID Card No",
        "Engineer ID No",
        "",
        "Gas Safe Register ID Card No",
        "Gas Safe License",
    ]
    features_list_3 = ["Location", "Appliance Location", "Appliance Type", "Type"]
    features_list_4 = [
        "Make/Model",
        "Make",
        "Model",
        "Manufacturer",
        "Appliance Make",
        "Appliance Model",
    ]
    features_list_5 = ["Flue Type", "Chimney Type", "Chimney/Flue Type", "Type of Flue"]
    features_list_6 = [
        "Landlords appliance",
        "Landlord's Appliance",
        "Owned by Landlord",
    ]
    features_list_7 = ["Appliance Insp", "Appliance Inspected"]
    features_list_8 = [
        "Combustion analyser reading",
        "Initial Combustion Analyser Reading/Final Combustion Analyser Reading",
        "Initial Combustion Analyser Reading",
    ]
    features_list_9 = [
        "Operating pressure or heat input",
        "Operating Pressure mbar or Heat Input",
        "Operating Pressure (mbars) or heat input (kW/h)",
        "Operating Pressure in mbar and or Heat Input in KW/Btu/h",
    ]
    features_list_10 = [
        "Safety device(s) correct operation",
        "Safety devices operating correctly",
        "Safety device(s) working correctly",
        "Are Safety Devices Working",
    ]
    features_list_11 = [
        "Ventilation provision satisfactory",
        "Satisfactory ventilation",
    ]
    features_list_12 = [
        "Visual condition of the flue & termination satisfactory",
        "Visual Condition of Chimney and Termination Satisfactory",
        "Visual condition of flue & termination",
        "Chimney termination & condition satisfactory",
        "Flue Visual Condition",
    ]
    features_list_13 = [
        "Flue performance checks",
        "Chimney Performance Test",
        "Flue operation checks",
        "Flue Performance Check",
    ]
    features_list_14 = [
        "Appliance serviced",
        "Appliance Service Completed",
        "Was appliance serviced",
        "Appliance serviced during visit",
    ]
    features_list_15 = [
        "Appliance safe to use",
        "Is appliance safe to use",
        "Appliance safe for continued use",
    ]
    features_list_16 = [
        "Approved CO alarm fitted",
        "CO alarm fitted and working",
        "Approved CO detector(s) installed",
    ]
    features_list_17 = ["Is CO alarm in date", "CO Detector(s) within service date"]
    features_list_18 = [
        "Testing of CO alarm satisfactory",
        "CO detector(s) test function operated",
        "Does the CO Alarm Work",
    ]
    features_list_19 = ["Number of appliances tested"]
    features_list_20 = [
        "Gas installation pipework (visual inspection) satisfactory?",
        "Gas installation pipe work satisfactory visual inspection",
        "Satisfactory visual inspection of gas installation pipework",
        "Gas pipework visual condition satisfactory",
        "Satisfactory Visual Condition",
    ]
    features_list_21 = [
        "Gas tightness test satisfactory?",
        "Outcome of gas tightness test",
        "Gas pipework tightness tested",
        "Satisfactory Gas Tightness Test",
    ]
    features_list_22 = [
        "Emergency control valve accessible?",
        "Is the emergency control accessible",
        "Emergency Control Accessible",
    ]
    features_list_23 = [
        "Protective equipotential bonding satisfactory?",
        "Equipotential bonding satisfactory",
        "Is the main protective equipotential bonding satisfactory",
        "Presence of protective bonding",
        "Equipotential Bonding Satisfactory",
    ]
    features_list_24 = ["Audible carbon monoxide alarm fitted?"]

    features_list = (
        features_list_1
        + features_list_2
        + features_list_3
        + features_list_4
        + features_list_5
        + features_list_6
        + features_list_7
        + features_list_8
        + features_list_9
        + features_list_10
        + features_list_11
        + features_list_12
        + features_list_13
        + features_list_14
        + features_list_15
        + features_list_16
        + features_list_17
        + features_list_18
        + features_list_19
        + features_list_20
        + features_list_21
        + features_list_22
        + features_list_23
        + features_list_24
    )
    features_found = find_features(features_list, clean_entities)

    # "Example Address received from form stored as json in s3 bucket"

    # Address line 1 = House number and street name
    # Address line 2 = area or village name
    # Address line 3 = Major town
    # Address line 4 = County
    # Address libe 5 = Post Code

    # doi - date of issue
    # date present
    # less than || equal to one year old

    # serial_number

    # flag if not found

    address_received = {}
    address_received["line1"] = "flat 8"
    address_received["line2"] = "60 sherwood park road"
    address_received["line3"] = "sutton"
    address_received["line4"] = "surrey"
    address_received["line5"] = "sm1 2sg"
    address_received["date"] = "10/01/2022"
    address_received["serial"] = "123456"

    address_1 = address(
        address_received["line1"],
        address_received["line2"],
        address_received["line3"],
        address_received["line4"],
        address_received["line5"],
        address_received["date"],
        address_received["serial"],
    )

    address_score = score_address(entities, address_received)

    if features_found == None:
        return {
            "statusCode": 400,
            "job_id": job_id,
            "job_tag": job_tag,
            "bucket": bucket,
            "temp_folder": temp_folder,
        }
    print("final_features_found", features_found)
    print("address_score", address_score)

    return {
        "statusCode": 200,
        "job_id": job_id,
        "job_tag": job_tag,
        "bucket": bucket,
        "temp_folder": temp_folder,
        "entities": clean_entities,
        "featuresFound": features_found["keys_found"] + features_found["values_found"],
        "confidence": features_found["score"],
        "address_score": address_score,
    }
