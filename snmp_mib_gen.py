import json
import snmp_json
from collections import OrderedDict
import os

def is_no_change_syntax(syntax_str):
    no_change_List=["InterfaceIndex", "AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex", 
                    "DS1TIMESLOT", "INTEGER", "Counter64", "Counter32", "Integer32"]
    if syntax_str in no_change_List :
        return 1
    
    return 0

class MibEntryGen():
    def __init__(self, name, index, json, type1="set", shift=1):
        self.name = name
        self.index = index
        self.json = json
        self.tab_space=4
        self.shift=shift
        self.type1=type1
        #print "--\n"+str(json)+"--\n"
        
    def __str__(self):
        mib_str=self.shift_space() + self.name + self.json["_name"]+ " OBJECT-TYPE\n"
        mib_str+=self.gen_syntax()
        mib_str+=self.gen_rw()
        mib_str+=self.shift_space(2)+"STATUS      current\n"
        mib_str+=self.gen_desc()
        mib_str+=self.shift_space(2)+"::= { "+self.name
        if self.type1 == "get":
            mib_str+="Entry"
        mib_str+=" "+ str(self.index)+" } \n\n"
        return mib_str
        
    def gen_syntax(self):
        syntax=self.shift_space(2)+"SYNTAX      "
        if self.json["_syntax"] == "intf":
            syntax+='DisplayString (SIZE(0..63))\n'
        elif self.json["_syntax"] == "display" or self.json["_syntax"] == "errMsg":
            syntax+='DisplayString (SIZE(0..255))\n'
        elif self.json["_syntax"] == "tunnel" or self.json["_syntax"] == "pw" or self.json["_syntax"] == "xc":
            syntax+='DisplayString (SIZE(0..43))\n'
        elif self.json["_syntax"] == "pwGrp":
            syntax+='DisplayString (SIZE(0..44))\n'
        elif isinstance(self.json["_syntax"], dict):
            syntax+="INTEGER {\n"
            for k,v in self.json["_syntax"].items():
                syntax+=self.shift_space(2)+"            "+v+"("+str(k)+"),\n"
                
            syntax+="MibEntryGen_gen_syntax_LAST"
            syntax=syntax.replace(",\nMibEntryGen_gen_syntax_LAST", "\n")
            syntax+=self.shift_space(2)+"            "+"}\n"
        elif self.json["_syntax"].startswith("range:"):
            range_str=self.json["_syntax"]
            syntax+="INTEGER ("
            splitor_index=range_str.find("-")
            startNum=range_str[len("range:"):splitor_index]
            endNum=range_str[splitor_index+1:]

            syntax+=startNum+".."+endNum+")\n"


        elif is_no_change_syntax(self.json["_syntax"]):
            syntax+= self.json["_syntax"]+'\n'
        else:
            print "mib_unknow syntax:" + self.json["_syntax"]
            syntax+= self.json["_syntax"]+'\n'
        
        return syntax
        
    def gen_rw(self):
        rw=self.shift_space(2)+"MAX-ACCESS  "
        
        #print "gen_rw"+ self.json["_rw"]
        if self.json["_rw"] == "r" :
            rw+="read-only"
        elif self.json["_rw"] == "rw" :
            rw+="read-write"
            
        rw+="\n"
        return rw
        
    def gen_desc(self):
        desc =self.shift_space(2)+"DESCRIPTION "
        desc+='"'+self.json["_desc"].replace("\n", "\n"+self.shift_space(2)+"             ")
        desc+='"\n'
        return desc
        
    def shift_space(self, tab_count=1):
        return " "*self.tab_space*tab_count*self.shift

class MibFileGen():
    def __init__(self, json):
        self.name=json["_name"]
        self.oid=str(json["_oid"])
        self.json = json
        if len(self.name)==0: 
            print "can not find name in " +str(json)
            return
            
        if len(json["_short_name"])==0: 
            self.short_name = self.name
        else :
            self.short_name=json["_short_name"]
            
        self.shift_index=json["_shift_index"]
        
    def gen(self):
        fname= self.name.lower()+"_01.00.mib"
        f= open(fname, "w+")
        self.gen_header(f)
        index=self.shift_index
        for k, v in self.json.items():
            if snmp_json.is_snmp_keyword(k)==0 :
                if v["_type"]=="set" :
                    self.gen_set_table(f, k, v, index)
                else :
                    self.gen_get_table(f, k, v, index)
                index+=1
        f.close() 
        
        os.system("cp " +fname+ " /var/www/html/download/temp.mib")
        os.system("cp " +fname+ " /home/bryant/Documents/vmshare/temp.mib")
        
    def gen_header(self, f):
        f.write("--============================================================================\n")
        f.write("-- "+self.name+"(."+self.oid+")\n")
        f.write("--============================================================================\n\n")
        
    def gen_set_table(self, f, tableName, tableContent, index):
        name=self.short_name+snmp_json.get_upper_start_str(tableName)
        f.write("    "+name+" OBJECT IDENTIFIER ::= { "+self.name+" "+str(index)+" }\n\n")
        
        index=1
        for k, v in tableContent.items():
            #print str(index)+"tableContent"+str(tableContent)+"!!"
            if snmp_json.is_snmp_keyword(k)==0 :
                entry=MibEntryGen(name, index, v)
                f.write(str(entry))
                index+=1

    def gen_get_table(self, f, tableName, tableContent, index):
        name=self.short_name+snmp_json.get_upper_start_str(tableName)
        f.write("--    "+name+"Table"+" OBJECT IDENTIFIER ::= { "+self.name+" "+str(index)+" }\n\n")
        
        
        f.write(self.shift_space()+name+"Table"+ " OBJECT-TYPE\n")
        f.write(self.shift_space(2)+"SYNTAX SEQUENCE OF "+snmp_json.get_upper_start_str(name)+"Entry\n")
        f.write(self.shift_space(2) + "MAX-ACCESS         not-accessible\n")
        f.write(self.shift_space(2) + "STATUS             current\n")
        f.write(self.gen_desc(tableContent["_table_desc"]))
        f.write(self.shift_space(2)+"::= {"+ self.name+ " "+str(index)+"}\n\n")
        
        f.write(self.shift_space()+name+"Entry"+ " OBJECT-TYPE\n")
        f.write(self.shift_space(2) + "SYNTAX     "+snmp_json.get_upper_start_str(name)+"Entry\n")
        f.write(self.shift_space(2) + "MAX-ACCESS         not-accessible\n")
        f.write(self.shift_space(2) + "STATUS             current\n")
        f.write(self.gen_desc(tableContent["_entry_desc"]))
        
        f.write(self.shift_space(2) + "INDEX              {")
        index_str=""
        for ele in tableContent["_get_table_index"]:
            index_str+=" "+name+ele+",\n"+self.shift_space(2)+"                    "
            
        index_str+="index_str_LAST"
        index_str=index_str.replace(",\n"+self.shift_space(2)+"                    "+"index_str_LAST", " ")
        f.write(index_str+"}\n")
        
        f.write(self.shift_space(2)+"::= {"+ name+ "Table 1 }\n\n")
        
        f.write(self.shift_space(2)+snmp_json.get_upper_start_str(name)+"Entry ::=\n")
        f.write(self.shift_space(4)+"SEQUENCE {\n")
        
        max_key_len=0;
        for k, v in tableContent.items():
            if snmp_json.is_snmp_keyword(k)==0 :
                if len(k) > max_key_len:
                    max_key_len=len(k)
        
        max_key_len+=len(name)
                    
        seq_str = ""
        for k, v in tableContent.items():
            if snmp_json.is_snmp_keyword(k)==0 :
                seq_str+=self.shift_space(5)+ self.get_std_key(name+k, max_key_len)+ self.gen_sequence_syntax(v["_syntax"])+",\n"
                
        seq_str+="gen_get_table_LAST"
        seq_str=seq_str.replace(",\ngen_get_table_LAST", "\n")
        f.write(seq_str)
        f.write(self.shift_space(5)+"}\n\n")
        
        index=1
        for k, v in tableContent.items():
            #print str(index)+"tableContent"+str(tableContent)+"!!"
            if snmp_json.is_snmp_keyword(k)==0 :
                entry=MibEntryGen(name, index, v, "get")
                f.write(str(entry))
                index+=1
                
    def shift_space(self, tab_count=1):
        return "    "*tab_count
        
    def gen_desc(self, ori_desc):
        desc =self.shift_space(2)+"DESCRIPTION\n"
        desc+=self.shift_space(3)
        desc+='"'+ori_desc.replace("\n", "\n"+self.shift_space(2)+"     ")
        desc+='"\n'
        return desc
        
    def gen_syntax(self, syntax_str):
        if syntax_str == "intf":
            syntax='DisplayString (SIZE(0..63))\n'
        elif syntax_str == "display" or syntax_str == "errMsg":
            syntax='DisplayString (SIZE(0..255))\n'
        elif syntax_str == "tunnel" or syntax_str == "pw" or syntax_str == "xc":
            syntax='DisplayString (SIZE(0..43))\n'
        elif syntax_str == "pwGrp":
            syntax='DisplayString (SIZE(0..44))\n'
        elif isinstance(syntax_str, dict):
            syntax="INTEGER"
        elif syntax_str.startswith("range:"):
            syntax="INTEGER"
        else:
            print "mib_gen_syntax unknow syntax:" + syntax_str
            syntax= syntax_str
            
        return syntax
        
    def gen_sequence_syntax(self, syntax_str):
        DisplayStringList=["intf", "display", "errMsg", "tunnel", "pw", "xc", "pwGrp"]
    
        if syntax_str in DisplayStringList:
            syntax='DisplayString'
        elif  isinstance(syntax_str, dict) :
            syntax="INTEGER"
        elif  syntax_str.startswith("range:"):
            syntax="INTEGER"
        elif is_no_change_syntax(syntax_str) :
            syntax= syntax_str
        else:
            print "mib_gen_sequence_syntax unknow syntax:" + syntax_str
            syntax= syntax_str
            
        return syntax
        
    def get_std_key(self, key, max_len):
        return key+" "*(max_len-len(key)+2)