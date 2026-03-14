import os
import hashlib

def read_file(file: str):
    try:
        with open(file=file, mode="r", encoding="utf-8") as f:
            can_txt = f.readlines()
        return can_txt
    except FileNotFoundError:
        print(f"Could not file specified file {file}")
    except PermissionError:
        print(f"Error access to file not permitted {file}")
    except UnicodeDecodeError:
        print(f"error could not encode {file} with utf-8 encoding ")
    except Exception as e:
        print(f"Unexpected error occured {e}")

def parseFrame(frames: str) -> dict:
    parseDict=[]
    for frame in frames:
        if "can0" in frame.strip().split():
            timestamp = frame.split()[0].strip("()").replace(" ", "")
            interface = frame.split()[1]
            ID = frame.split()[2].split("#")[0]
            data = frame.split()[2].split("#")[1]
            message_dict = {"timestamp": timestamp,
                            "interface": interface,
                            "ID": ID,
                            "data": data}
            parseDict.append(message_dict)
    return parseDict

def convertToHex(num: int) -> hex:
    length = (num.bit_length() + 7) //8
    return num.to_bytes(length=length, byteorder='big').hex()

def convertToDec(num: bytes) -> int:
    return int.from_bytes(num, byteorder='big')

def extract_data(data: dict) -> dict:
    counter = []
    for value in data:
        val = value.get("data")
        payload = bytes.fromhex(val)
        count = int.from_bytes(payload[:1], "little")
        count = {"counter": count}
        counter.append(count)
    return counter

def parseLine(lines: str) -> dict:
    parse_dict = []
    for line in lines:
        line = line.strip()
        if not line.startswith("("):
            raise ValueError("Invalid frame format")
        
        # extract timestamp
        right_paren = line.find(")")
        if right_paren == -1:
            raise ValueError("Invalid line format")
        timestamp = line[1:right_paren]
        rest = line[right_paren+1:].strip()
        parts = rest.split()
        if len(parts) != 2:
            raise ValueError("Invalid line format")
        identifier = parts[0]
        if '#' not in parts[1]:
            raise ValueError("Invalid line format")
        can_id, data = parts[1].split('#', 1)
        parse_can = {"timestamp": timestamp,
                     "identifier": identifier,
                     "can_id": can_id,
                     "data": data}
        parse_dict.append(parse_can)
    return parse_dict

def raw_from_bytes_and_list(payload: str):
    payload = payload.strip()
    if len(payload) % 2 != 0:
        raise ValueError("Invalid payload")
    raw_bytes = bytes.fromhex(payload)
    int_list = list(raw_bytes)
    return raw_bytes, int_list

def filter_raw_log(raw_log: str, target_can_id: str):
    results = []
    with open(raw_log, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if not line:
                continue
            
            try:
                frame = parseLine(line)
            except Exception:
                continue

            if frame["can_id"] == target_can_id:
                results.append(frame)
    return results

def validate_security_access(raw_log: str, secret: bytes):
    frames = parseLine(raw_log)

    challenge = None
    response = None
    for frame in frames:
        payload = bytes.fromhex(frame['data'])
        if(len(payload) < 2):
            continue
        service = payload[0]
        sub = payload[1]
        if service == 0x67 and sub == 0x01:
            challenge = payload[2:]
        if service == 0x27 and sub == 0x02:
            response = payload[2:]
        elif challenge is None or response is None:
            return {"found": False,
                    "status": "Incomplete security challenge rsponse sequence"}
    h = hashlib.sha256()
    h.update(secret)
    h.update(response)
    expected = h.digest()[:len(response)]
    return {"found": True,
            "challenge": challenge,
            "response": response,
            "expected": expected,
            "status": expected == response}

if __name__ == "__main__":
    file = "messages.txt"
    can_txt = read_file(file)
    parse_dict = parseLine(can_txt)
    print(parse_dict)
    raw_bytes = raw_from_bytes_and_list(parse_dict[0]['data'])
    print(raw_bytes[0])
    print("\n")
    print(raw_bytes[1])

    h = hashlib.sha256()
    h.update(secret)
    h.update(response)
    expected = h.digest()[:len(response)]
    #results = filter_raw_log(file, target_can_id='can0')
    #print("\n")
    #print(results)
    #parse_can = parseFrame(can_txt)
    #print(parse_can)
    #int_data = int(parse_can[0].get('data'))
    #hex_data = convertToHex(int_data)
    #print(f"hex code: {hex_data}")
    #counter = extract_data(parse_can)
    #print(counter)