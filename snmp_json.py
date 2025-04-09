import json
from collections import OrderedDict

def newJson():
    return json.loads("{}", object_pairs_hook=OrderedDict)

class SnmpObj():
    def __init__(self, name, oid, short_name="", shift_index=1 ):
        self.json=newJson()
        self.json["_name"]=name
        self.json["_oid"]=oid
        if len(short_name) ==0 :
            self.json["_short_name"]=name
        else:
            self.json["_short_name"]=short_name
            
        self.json["_shift_index"]=shift_index
        self.json["_tab_space"]=4
            
            
    def add_table(self, table):
        self.json[table["_name"]]=table
        
    def show(self, space_count=0):
        for k,v in self.json.items() :
            if isinstance(v, str) or isinstance(v, int) or isinstance(v, list) or isinstance(v, OrderedDict):
                print " "*space_count + str(k) + ":" +str(v)
            else :
                print " "*space_count + "{"
                v.show(space_count+4)
                print " "*space_count + "},"
        
    def __getitem__(self, key):
        return self.json[key]
        
    def items(self):
        return self.json.items()
        
    def dump(self):
        return str(self.json)
        
class SnmpTable():
    def __init__(self, name, type1, get_table_index=[""], table_desc="", entry_desc=""):
        self.json=newJson()
        self.json["_name"]=name
        self.json["_type"]=type1
        self.json["_get_table_index"]=get_table_index
        self.json["_table_desc"]=get_std_desc(table_desc, 48)
        self.json["_entry_desc"]=get_std_desc(entry_desc, 48)
        
    def add_entry(self, entry):

        if self.json.get(entry["_name"]) != None:
            raise Exception("duplicate entry:"+entry["_name"])
        
        self.json[entry["_name"]]=entry
        
    def __getitem__(self, key):
        return self.json[key]
        
    def items(self):
        return self.json.items()
        
    def dump(self):
        return str(self.json)

    def show(self, space_count=0):
        for k,v in self.json.items() :
            if isinstance(v, str) or isinstance(v, int) or isinstance(v, list) or isinstance(v, OrderedDict):
                print " "*space_count + str(k) + ":" +str(v)
            else :
                print " "*space_count + "{"
                v.show(space_count+4)
                print " "*space_count + "}"
        
class SnmpEntry():
    def __init__(self, name, syntax, rw, desc):
        self.json=newJson()
        self.json["_name"]=name
        #self.json["_syntax"]=syntax
        self.json["_rw"]=rw
        
        #print std_desc

        if syntax=="TruthValue":
            syntax=["true", "false"]
    
        if isinstance(syntax, list):
            syntaxEnum=newJson();
            for i in range(1, 1+len(syntax)):
                syntaxEnum[i]=syntax[i-1]
                
            self.json["_syntax"]=syntaxEnum
        else :
            self.json["_syntax"]=syntax

        self.json["_desc"]=get_std_desc(desc)
    
    def __getitem__(self, key):
        return self.json[key]
    
    def __setitem__(self, key, newvalue):
        self.json[key]=newvalue
        
    def items(self):
        return self.json.items()
        
    def dump(self):
        return str(self.json)

    def show(self, space_count=0):
        for k,v in self.json.items() :
            if isinstance(v, str) or isinstance(v, int) or isinstance(v, list) or isinstance(v, OrderedDict):
                print " "*space_count + str(k) + ":" +str(v)
            else :
                print " "*space_count + "{"
                v.show(space_count+4)
                print " "*space_count + "}"
    
def newJson():
    return json.loads("{}", object_pairs_hook=OrderedDict)

def get_upper_start_str(ori_str):
    #print "get_upper_start_str:" + ori_str
    if(len(ori_str)==0) :
        return ori_str
    
    return ori_str[0].upper()+ori_str[1:]

def get_lower_start_str(ori_str):
    #print "get_lower_start_str:" + ori_str
    if(len(ori_str)==0) :
        return ori_str
    
    return ori_str[0].lower()+ori_str[1:]
    
def is_snmp_keyword(k):
        if k.startswith("_"):
            return 1
        else :
            return 0
            
def is_snmp_string(v):
    string_list=["DS1TIMESLOT", "display", "tunnel", "pw", "xc", "intf", "errMsg", "pwGrp", "DisplayString"]
    if v in string_list:
        return 1
    else :
        return 0

def is_snmp_integer(v):
    integer_list=["INTEGER", "AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex", "InterfaceIndex", "Integer32", 
    "TimeStamp", "TimeTicks", "Unsigned32"]
    if v in integer_list:
        return 1
    else :
        return 0

def is_snmp_unsigned_integer(v):
    integer_list=["AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex", "InterfaceIndex", 
    "TimeStamp", "TimeTicks", "Unsigned32", "Gauge32"]
    if v in integer_list:
        return 1
    else :
        return 0

def is_snmp_sdh_index(v):
    integer_list=["AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex"]
    if v in integer_list:
        return 1
    else :
        return 0
            
def get_std_desc(desc, line_limit=40):
    desc=get_upper_start_str(desc).strip()
    if not desc.endswith(".") :
        desc +="."
    
    str_list= desc.split( )
        
    std_desc=""
    line =""
    for ele in str_list :
        line+= ele+" "
        if len(line)> line_limit :
            std_desc+=line+"\n"
            line=""
    
    std_desc += line
    return std_desc.strip()
    