import json
import snmp_json
import os


def delete_file(path):
    yn=raw_input( "delete " + path+" ? (y to contunue):" )

    if(yn=="y"):
        os.system("rm -r " + path)
        #print "rm " + path + " fail. raise Exception"
    else :
        print "rm " + path + " fail."
        raise Exception("delete file fail!")


def is_c_keyword(v):
    keyword_list=["int", "switch"]
    if v.lower() in keyword_list:
        return 1

    return 0

def is_c_snmp_integer(v):
    integer_list=["Integer32", "Counter64", "Counter32"]
    if v in integer_list:
        return 1
    else :
        return 0

def get_syntax_snmpc_type(syntax):
        if snmp_json.is_snmp_string(syntax):
            return "ASN_OCTET_STR"
        elif syntax=="Gauge32":
            return "ASN_GAUGE"
        elif isinstance(syntax, dict) or snmp_json.is_snmp_integer(syntax):
            return "ASN_INTEGER"
        elif syntax.startswith("range:"):
            return "ASN_INTEGER"
        elif syntax=="Unsigned32" or syntax=="TimeStamp":
            return "ASN_UNSIGNED"
        elif syntax=="Counter64":
            return "ASN_COUNTER64"
        elif syntax=="Counter32":
            return "ASN_COUNTER"
        else :
            print "snmpc_json.get_syntax_snmpc_type_not imp "+ syntax
            raise Exception("snmpc_json.get_syntax_snmpc_type_not imp "+ syntax)
            return "snmpc_json.get_syntax_snmpc_type_not imp"



class CSyntaxHandle():
    def __init__(self, name, static_handle, column_obj_handle):
        self.name=name
        self.static_handle=static_handle
        self.column_obj_handle=column_obj_handle

syntax_list=["DS1TIMESLOT", 
            "display", "tunnel", "pw", "xc", "intf", "errMsg", "pwGrp",
            "INTEGER", "InterfaceIndex", "AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex", 
            "_dict"]

syntax_handle_list=[]


def is_no_change_syntax(syntax_str):
    no_change_List=["InterfaceIndex", "AUG1STS3Index", "VC3STS1Index", "VC1xVTxIndex", "DS1TIMESLOT", "INTEGER", "TimeStamp"]
    if syntax_str in no_change_List :
        return 1
    
    return 0


###########set CEntryGen
class CEntryGen():
    def __init__(self, oid, table_oid, index, obj_name, table_name, json, type1="set"):
        if len(syntax_handle_list)==0:
            syntax_handle_list.append(CSyntaxHandle("pwGrp", self.gen_static_pwGrp_str, self.gen_column_obj_pwGrp_str))

        self.oid=oid
        self.table_oid=table_oid
        self.index=index
        self.obj_name=obj_name
        self.table_name=table_name

    

        syntax=json["_syntax"]
        if isinstance(syntax, dict):
            for k,v in syntax.iteritems():
                if "-" in v :
                    syntax[k]=v.replace("-", "_")

                if is_c_keyword(v) :
                    syntax[k]=v+"1"

        json["_syntax"]=syntax

        if is_c_keyword(json["_name"]) :
            json["_name"]=json["_name"]+"1"

        self.json=json
        self.prefix=obj_name + get_upper_start_str(table_name)

        
        if type1=="get":
            self.prefix+="Table"
        
        self.entry_name=self.prefix+ get_upper_start_str(self.json["_name"])
        self.static="s"+get_upper_start_str(self.entry_name)
        
        self.type1=type1
        
        self.column_enum=""
        #print "CEntryGen"
        #print json
        
    def gen_enum_str(self):
        enum=""
        if isinstance(self.json["_syntax"], dict):
            #print "dict"+ str(self.json["_syntax"])
            enum_def=(self.obj_name+"_"+self.table_name+"_"+self.json["_name"]).upper()
            enum+="typedef enum{\n"
            for k,v in self.json["_syntax"].items():
                enum+="    "+ enum_def+"_"+v.upper()+"="+str(k)+",\n"
            enum+="}"+enum_def+";\n\n"
           
        #replace sepcail char
        #enum=enum.replace("-", "_")
            
        return enum

    def gen_static_pwGrp_str(self):
        return "char " + self.static +'[OS_MAC_PW_RED_GROUP_NAME_LEN]="";\n'
        
    def gen_static_str(self):
        static="static "
        if self.json["_syntax"] == "display":
            static+="char " + self.static +'[256]="";\n'
        elif self.json["_syntax"] == "intf":
            static+="char " + self.static +'[64]="";\n'
        elif self.json["_syntax"] == "tunnel":
            static+="char " + self.static +'[OS_MAC_MPLS_TUNNEL_NAME_LEN]="";\n'
        elif self.json["_syntax"] == "pw":
            static+="char " + self.static +'[OS_MAC_PW_NAME_SIZE]="";\n'
        elif self.json["_syntax"] == "pwGrp":
            static+="char " + self.static +'[OS_MAC_PW_RED_GROUP_NAME_LEN]="";\n'
        elif self.json["_syntax"] == "xc":
            static+="char " + self.static +'[OS_MAC_XCONNECT_NAME_SIZE]="";\n'
        elif self.json["_syntax"] == "errMsg":
            static+="char " + self.static +'[LOOPOS_CONFIG_GENERAL_USER_ERROR_MESSAGE_MAX_LENGTH+1]="";\n'
        elif self.json["_syntax"] == "DS1TIMESLOT":
            static+="char " + self.static +'[4]="";\n'
        elif isinstance(self.json["_syntax"], dict):
            enum_def=(self.obj_name+"_"+self.table_name+"_"+self.json["_name"]).upper()
            static+="int " + self.static +'='+enum_def+"_"+self.json["_syntax"][self.json["_syntax"].keys()[0]].upper()+';\n'
        elif self.json["_syntax"] == "AUG1STS3Index" or self.json["_syntax"] == "VC3STS1Index" or self.json["_syntax"] == "VC1xVTxIndex":
            static+="int " + self.static +'=255;\n'
        elif snmp_json.is_snmp_integer(self.json["_syntax"]):
            static+="int " + self.static +'=0;\n'
        else :
            print "c_gen_static_str unknow:" + self.json["_syntax"] + " " +self.static
            raise Exception("c_gen_static_str unknow:" + self.json["_syntax"] + " " +self.static)
            static+="int " + self.static +'=0;\n'
            
        return static
    
    def gen_oid_str(self):
        oid= "    static oid "+self.entry_name+"_oid[] =\n"
        oid+="        { 1, 3, 6, 1, 4, 1, 823, 0, "+ str(self.oid)+", "+str(self.table_oid)+", "+str(self.index)+" };\n"
        return oid
        
    def gen_reg_str(self):
        reg= "    netsnmp_register_scalar(netsnmp_create_handler_registration\n"
        reg+='                            ("'+self.entry_name+ '",\n'
        reg+='                            handle_'+self.entry_name+',\n'
        reg+='                            '+self.entry_name+'_oid,\n'
        reg+='                            OID_LENGTH('+self.entry_name+'_oid),\n'
        if self.json["_rw"] == "rw" :
            reg+='                            HANDLER_CAN_RWRITE));\n'
        elif self.json["_rw"] == "r" :
            reg+='                            HANDLER_CAN_RONLY));\n'
            
        return reg
        
    def gen_func_str(self):
        func='''int
handle_REPLCAE_ENTRY_NAME(netsnmp_mib_handler *handler,
                        netsnmp_handler_registration *reginfo,
                        netsnmp_agent_request_info *reqinfo,
                        netsnmp_request_info *requests)
{
    int             ret;
    
    switch(reqinfo->mode) {
    case MODE_GET:
        REPLCAE_ENTRY_GET
        break;
    case MODE_SET_RESERVE1:
        REPLCAE_RNAGE_CHECK
        break;
    case MODE_SET_RESERVE2:
        break;
     case MODE_SET_FREE:
        break;
    case MODE_SET_ACTION:
        REPLCAE_ENTRY_SET
        break;
    case MODE_SET_COMMIT:
        break;
    case MODE_SET_UNDO:
        break;
    default:
        /*
         * we should never get here, so this is a really bad error 
         */
        snmp_log(LOG_ERR,
                 "unknown mode (%d) in handle_REPLCAE_ENTRY_NAME\\n",
                 reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;
}\n\n'''

        func=func.replace("REPLCAE_ENTRY_NAME", self.entry_name)
        snmp_get=""
        snmp_set="\n"
        snmp_range_check="//range check here\n"
        if snmp_json.is_snmp_string(self.json["_syntax"]):
            len_measure="strlen"
            if self.json["_syntax"]== "DS1TIMESLOT":
                len_measure="sizeof"

            snmp_get= "snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR,\n"
            snmp_get+="                                    (u_char *) &"+self.static+", "+len_measure+"("+self.static+"));\n"
            
            snmp_set= "memset("+self.static+", 0x00, sizeof("+self.static+"));\n"
            snmp_set+="        memcpy("+self.static+", requests->requestvb->val.string, requests->requestvb->val_len);\n"
        elif isinstance(self.json["_syntax"], dict) or snmp_json.is_snmp_integer(self.json["_syntax"]) :
            snmp_get= "snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,\n"
            snmp_get+="                                    (u_char *) &"+self.static+", sizeof("+self.static+"));\n"
            snmp_set= self.static+"=*(requests->requestvb->val.integer);\n"
            
        func=func.replace("REPLCAE_ENTRY_GET\n", snmp_get)
        
        if self.json["_rw"] == "rw" :
            func=func.replace("REPLCAE_ENTRY_SET\n", snmp_set)
        elif self.json["_rw"] == "r" :
            func=func.replace("REPLCAE_ENTRY_SET\n", "//read only\n")
            
        if self.json["_rw"] == "rw" :
            if isinstance(self.json["_syntax"], dict) :
                enum_def=(self.obj_name+"_"+self.table_name+"_"+self.json["_name"]).upper()
                snmp_range_check_str="""ret = netsnmp_check_vb_int_range(requests->requestvb, RANGE_MIN, RANGE_MAX);
        if(ret != SNMP_ERR_NOERROR) {
            netsnmp_set_request_error(reqinfo, requests, ret);
        }\n"""
                rnage_min=enum_def+"_"+self.json["_syntax"][self.json["_syntax"].keys()[0]].upper()
                rnage_max=enum_def+"_"+self.json["_syntax"][self.json["_syntax"].keys()[-1]].upper()
                snmp_range_check_str=snmp_range_check_str.replace("RANGE_MIN", rnage_min)
                snmp_range_check_str=snmp_range_check_str.replace("RANGE_MAX", rnage_max)
                snmp_range_check=snmp_range_check_str
            elif snmp_json.is_snmp_string(self.json["_syntax"]):
                snmp_range_check_str="""ret = netsnmp_check_vb_nvt_ascii_and_size_range(requests->requestvb,
                                                        0, sizeof(RANGE_STR_MAX)-1);
        if (ret != SNMP_ERR_NOERROR) {
            netsnmp_set_request_error(reqinfo, requests, ret);
        }\n"""
                snmp_range_check_str=snmp_range_check_str.replace("RANGE_STR_MAX", self.static)
                snmp_range_check=snmp_range_check_str
                
        func=func.replace("REPLCAE_RNAGE_CHECK\n", snmp_range_check)
        return func
        
    def gen_h_func_str(self):
        hfunc="Netsnmp_Node_Handler handle_"+self.entry_name+";\n"
        return hfunc
        
    def gen_column_enum_str(self):
        self.column_enum="COLUMN_"+(self.obj_name+"_"+self.table_name).upper() +"_"+self.json["_name"].upper()
        column_str="    "+self.column_enum+"="+str(self.index)+",\n"
        return column_str

    def gen_column_obj_pwGrp_str(self):
        column_obj_str ="        0,\n"
        column_obj_str+="        OS_MAC_PW_RED_GROUP_NAME_LEN,\n"
        return column_obj_str
        
    def gen_column_obj_str(self):
        syntax = self.json["_syntax"]

        column_obj_str ="    {\n"
        column_obj_str+="        "+self.column_enum+",\n"
        column_obj_str+="        "+get_syntax_snmpc_type(self.json["_syntax"])+",\n"
        if isinstance(syntax, dict) :
            column_obj_str+="        0,\n"
            column_obj_str+="        32767,\n"
        elif snmp_json.is_snmp_unsigned_integer(syntax):
            column_obj_str+="        0,\n"
            column_obj_str+="        0xffffffff,\n"
        elif snmp_json.is_snmp_integer(syntax):
            column_obj_str+="        0,\n"
            column_obj_str+="        32767,\n"
        elif syntax.startswith("range:"):
            splitor_index=syntax.find("-")
            startNum=syntax[len("range:"):splitor_index]
            endNum=syntax[splitor_index+1:]
            column_obj_str+="        "+startNum+",\n"
            column_obj_str+="        "+endNum+",\n"
        elif syntax== "Counter64":
            column_obj_str+="        0,\n"
            column_obj_str+="        sizeof(U64),\n"
        elif syntax== "Counter32":
            column_obj_str+="        0,\n"
            column_obj_str+="        sizeof(u_long),\n"
        elif syntax== "Integer32":
            column_obj_str+="        -2147483648,\n"
            column_obj_str+="        2147483647,\n"
        elif syntax== "intf":
            column_obj_str+="        0,\n"
            column_obj_str+="        64,\n"
        elif syntax== "xc" or syntax== "pw" or syntax== "pwGrp" :
            column_obj_str+="        0,\n"
            column_obj_str+="        44,\n"
        elif syntax== "display" or syntax== "DisplayString":
            column_obj_str+="        0,\n"
            column_obj_str+="        255,\n"
        elif syntax== "DS1TIMESLOT":
            column_obj_str+="        0,\n"
            column_obj_str+="        4,\n"
        elif syntax== "AUG1STS3Index" or syntax== "VC3STS1Index" or syntax== "VC1xVTxIndex":
            column_obj_str+="        0,\n"
            column_obj_str+="        255,\n"
        elif syntax== "errMsg":
            column_obj_str+="        0,\n"
            column_obj_str+="        255,\n"
        else :
            raise Exception("gen_column_obj_str!!!"+syntax+"!!!_not_imp_yet\n")
            #print "gen_column_obj_str " + syntax + " not_imp"
            column_obj_str+="        0,\n"
            column_obj_str+="        65535,\n"
            
        
        column_obj_str+="        (void *)"+self.prefix+"_find_row,\n"
        column_obj_str+="        (void *)"+self.prefix+"_find_next_row,\n"
        column_obj_str+="        (void *)get_"+self.entry_name+",\n"
        
        if self.json["_rw"] == "r" :
            column_obj_str+="        NULL,\n"
            column_obj_str+="        NULL,\n"
            column_obj_str+="        NULL,\n"
        elif self.json["_rw"] == "rw" :
            column_obj_str+="        (void *)set_"+self.entry_name+",\n"
            column_obj_str+="        (void *)check_"+self.prefix+"_ret_no_err,\n"
            column_obj_str+="        NULL\n"
       	
        column_obj_str+="    },\n"
        return column_obj_str
        
    def gen_get_access_func_def(self):
        type_def="int"
        if snmp_json.is_snmp_string(self.json["_syntax"]):
            type_def="char"
        elif self.json["_syntax"]=="Counter64":
            type_def="U64"
        elif self.json["_syntax"]=="Counter32":
            type_def="u_long"

        func_def = type_def+"* get_"+self.entry_name+"(void *data_context, size_t *ret_len);\n"
        if self.type1=="get" and self.json["_rw"] == "rw":
            func_def+= "int set_"+self.entry_name+"(void *data_context, long *val, size_t val_len);\n"
        return func_def
        
    def gen_get_access_func(self, addtion_access=""):
        lower_name = snmp_json.get_lower_start_str(self.json["_name"])

        type_def="int"
        len_measure="sizeof"
        ref_str="&"
        if snmp_json.is_snmp_string(self.json["_syntax"]):
            type_def="char"
            if self.json["_syntax"] !="DS1TIMESLOT":
                len_measure="strlen"
            ref_str="(char*) "
        elif self.json["_syntax"]=="Counter64":
            type_def="U64"
            ref_str="(U64 *)&"
        elif self.json["_syntax"]=="Counter32":
            type_def="u_long"
            #ref_str="(U64 *)&"

        func_def = type_def+"*\n"
        func_def+="get_"+self.entry_name+"(void *data_context, size_t *ret_len)\n"
        func_def+="{\n"
        if len(addtion_access) > 0 :
            func_def+=addtion_access+"\n"

        func_def+="    *ret_len = "+len_measure+"(row_entry."+lower_name+");\n"
        func_def+="    return "+ref_str+"row_entry."+lower_name+";\n"
        func_def+="}\n\n"

        if self.type1=="get" and self.json["_rw"] == "rw":
            func_def+="int\n"
            func_def+="set_"+self.entry_name+"(void *data_context, long *val, size_t val_len)\n"
            func_def+="{\n"
            func_def+="    struct "+self.prefix+"_entry *row = &row_entry;\n"
            func_def+="/*other def */\n\n"
            func_def+="""    if(row == NULL){
        return (SNMP_ERR_GENERR);
    }
"""
            func_def+="/* real set */\n\n"
            func_def+="    return SNMP_ERR_NOERROR;\n"
            func_def+="}\n\n"
            
            
        return func_def
        
    def gen_row_memeber(self):
        syntax = self.json["_syntax"]
        row_member="    "
        lower_name = snmp_json.get_lower_start_str(self.json["_name"])

        if isinstance(syntax, dict) :
            row_member+="int " + lower_name+";\n"
        elif snmp_json.is_snmp_unsigned_integer(syntax):
            row_member+="OS_U32 " + lower_name+";\n"
        elif snmp_json.is_snmp_integer(syntax):
            row_member+="int " + lower_name+";\n"
        elif syntax.startswith("range:"):
            row_member+="int " + lower_name+";\n"
        elif syntax=="Unsigned32" or syntax=="TimeStamp":
            row_member+="OS_U32 " + lower_name+";\n"
        elif syntax=="Counter64":
            row_member+="U64 " + lower_name+";\n"
        elif syntax=="Counter32":
            row_member+="u_long " + lower_name+";\n"
        elif syntax=="Integer32":
            row_member+="long " + lower_name+";\n"
        elif syntax=="xc":
            row_member+="char " + lower_name+"[OS_MAC_XCONNECT_NAME_SIZE];\n"
        elif syntax=="display" or syntax=="DisplayString":
            row_member+="char " + lower_name+"[255];\n"
        elif syntax=="intf":
            row_member+="char " + lower_name+"[64];\n"
        elif syntax=="DS1TIMESLOT":
            row_member+="char " + lower_name+"[4];\n"
        elif syntax=="errMsg":
            row_member+="char " + lower_name+"[LOOPOS_CONFIG_GENERAL_USER_ERROR_MESSAGE_MAX_LENGTH+1];\n"
        elif syntax=="pw":
            row_member+="char " + lower_name+"[OS_MAC_PW_NAME_SIZE];\n"
        elif syntax=="pwGrp":
            row_member+="char " + lower_name+"[OS_MAC_PW_RED_GROUP_NAME_LEN];\n"
        else :
            raise Exception("c_gen_row_memeber_!!!"+syntax+"!!!_not_imp_yet "+"int " + lower_name+";\n")
            #row_member+="c_gen_row_memeber_"+syntax+"_not_imp_yet "+"int " + lower_name+";\n"
        return row_member
        
    def gen_row_memeber_default(self):
        syntax = self.json["_syntax"]
        row_memeber_default="    row->"
        lower_name = snmp_json.get_lower_start_str(self.json["_name"])

        #print syntax

        if isinstance(syntax, dict) :
            enum_def=(self.obj_name+"_"+self.table_name+"_"+self.json["_name"]).upper()
            row_memeber_default+= lower_name+"="+enum_def+"_"+self.json["_syntax"].items()[0][1].upper()+";\n"
        elif syntax.startswith("range:"):
            splitor_index=syntax.find("-")
            startNum=syntax[len("range:"):splitor_index]
            row_memeber_default+= lower_name+"="+startNum+";\n"
        elif snmp_json.is_snmp_sdh_index(syntax):
            row_memeber_default+= lower_name+"=NOT_AVAILABLE_SDH_INDEX;\n"
        elif syntax=="Counter64":
            row_memeber_default ="    ASSIGN64(row->"+lower_name+", U64_ZERO);\n"
        elif is_c_snmp_integer(syntax) or snmp_json.is_snmp_integer(syntax):
            row_memeber_default+= lower_name+"=0;\n"
        elif snmp_json.is_snmp_unsigned_integer(syntax):
            row_memeber_default+= lower_name+"=0;\n"
        elif snmp_json.is_snmp_string(syntax):
            row_memeber_default+= lower_name+"[0]=0x00;\n"
        else :
            raise Exception("c_gen_row_memeber_default_!!!"+lower_name+"!!!_not_imp_yet "+"int " + lower_name+";\n")
            #row_memeber_default+="c_gen_row_memeber_default_"+lower_name+"_not_imp_yet "+"int " + lower_name+";\n"
        return row_memeber_default


    def gen_transfer_ts(self):
        transfer_str="""
static unsigned int
bit_reverse(unsigned int x)
{
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
    return((x >> 16) | (x << 16));
} 

static int 
loopos_ts_to_snmp_ts(OS_U32 bert_ts, char *snmp_ts)
{
    bert_ts=bit_reverse(bert_ts>>1);
    snmp_ts[0]= (bert_ts>>24)&0xff;
    snmp_ts[1]= (bert_ts>>16)&0xff;
    snmp_ts[2]= (bert_ts>>8)&0xff;
    snmp_ts[3]= (bert_ts>>0)&0xff;

    return 0;
}

static unsigned int 
snmp_ts_to_loopos_ts(char * snmp_ts)
{
    unsigned int timeslots = 0;
    int i =0;
    for(i=0; i<4; i++)
    {
        char val=snmp_ts[i];
        // Reverse bit ordering 
        val=((val&0xF0)>>4)|((val&0x0F)<<4);
        val=((val&0xCC)>>2)|((val&0x33)<<2);
        val=((val&0xAA)>>1)|((val&0x55)<<1);    
        timeslots|=val<<(8*i);
    }   
    // In MIB, bit0 reresents TS0, but in CC API, bit1 represents TS0. 
    timeslots<<=1;
    return timeslots;
}
"""
        return transfer_str

    def gen_transfer_enable_disable(self):
        to_loopos_enum=""
        to_snmp_enum=""
        enum_def=(self.obj_name+"_"+self.table_name+"_"+self.json["_name"]).upper()

        for k,v in self.json["_syntax"].items():
            #print(k,v)
            if v =="enable":
                to_loopos_enum+="        case "+ enum_def+"_"+v.upper()+":\n"
                to_loopos_enum+="            return OS_ENU_COMM_STATE_TYPE_ENABLE;\n"
                to_snmp_enum+="        case OS_ENU_COMM_STATE_TYPE_ENABLE:\n"
                to_snmp_enum+="            return "+enum_def+"_"+v.upper()+";\n"
            elif v =="disable":
                to_loopos_enum+="        case "+ enum_def+"_"+v.upper()+":\n"
                to_loopos_enum+="            return OS_ENU_COMM_STATE_TYPE_DISABLE;\n"
                to_snmp_enum+="        case OS_ENU_COMM_STATE_TYPE_DISABLE:\n"
                to_snmp_enum+="            return "+enum_def+"_"+v.upper()+";\n"

        #to_loopos_enum=to_loopos_enum.replace("-", "_")
        #to_snmp_enum=to_snmp_enum.replace("-", "_")
        transfer_str="""
static int 
snmp_state_to_loopos_state(int state)
{
    switch(state){
C_FILE_GEN_SNMP_TO_LOOP_STRING        default:
            return -1;
    }
    return -1;
}

static int 
loopos_state_to_snmp_state(int state)
{
    switch(state){
C_FILE_GEN_LOOP_TO_SNMP_STRING        default:
            return -1;
    }
    return -1;
}
"""
        transfer_str=transfer_str.replace("C_FILE_GEN_SNMP_TO_LOOP_STRING", to_loopos_enum)
        transfer_str=transfer_str.replace("C_FILE_GEN_LOOP_TO_SNMP_STRING", to_snmp_enum)

        return transfer_str

    def gen_transfer_function_str(self):
        transfer_str=""
        syntax = self.json["_syntax"]
        if syntax=="DS1TIMESLOT":
            transfer_str+=self.gen_transfer_ts()
        elif isinstance(syntax, dict):
            if "enable" in syntax.values() and "disable" in syntax.values() :
                transfer_str+=self.gen_transfer_enable_disable()

        return transfer_str
###########set CEntryGen
        
        
        
        
        






        
        
        
        
        
        
        
        
        
        
        
        
        
        

class CTableGen():
    def __init__(self, oid, index, tittle, name, json):
        self.enum_str=""
        self.static_str=""
        self.oid_str=""
        self.reg_str=""
        self.func_str=""
        self.h_func_str=""
        
        self.column_enum_str=""
        self.column_obj_str=""
        self.h_access_func_str=""
        self.c_access_func_str=""
        self.row_struct_member=""
        self.row_memeber_default_str=""
        self.transfer_function_str=""
        
        self.oid=oid
        self.index=index
        self.tittle=tittle
        self.name=name
        self.json = json

        self.extra_header=""
        self.extra_header+='\n#include "'+"ctrl/cmd/sdh_cmd.h"+'"\n'
        self.extra_header+='#include "'+"netif/ifapi.h"+'"\n'
        self.extra_header+='#include "'+"ctrl/controller/config.h"+'"\n'
        self.extra_header+='#include "'+"ctrl/cmd/pw_red_cmd.h"+'"\n'
        self.extra_header+='#include "'+"common/os_pm.h"+'"\n'
        #self.extra_header+='#include "'+"prod_cc/cmd/prod_cmd.h"+'"\n'
        
        self.table_name=self.tittle + get_upper_start_str(self.name)
        if self.is_get() :
            self.table_name+="Table"
            
        self.column_def="COLUMN_"+(self.tittle+"_"+self.name).upper()#+"_"
        
        self.addtion_func="""static int 
get_pwred_ac_name(char* grp_name, int ac_index, char* ac_name)
{
    snprintf(ac_name, OS_MAC_PW_RED_GROUP_NAME_LEN, "%s:AC%d", grp_name, ac_index+1);
    return 0;
}\n"""

        self.addtion_access="""    OS_STR_PM_INTERVAL_DATA perf;
    char name[OS_MAC_PW_RED_GROUP_NAME_LEN];
    int ret;

    get_pwred_ac_name(row_entry.grpName, row_entry.acIndex, name);

    ret=osPmPwTdmPerformanceGet(name, OS_ENU_PW_PERF_TYPE_OUT_PKTS, &perf);
    if(ret)
        return NULL;

    ASSIGN64(row_entry.outPkts, perf.pmdata.current_15m);\n\n"""

        self.addtion_func=""
        self.addtion_access=""

        self.gen()
        
    def gen(self):
        if self.json["_type"] == "set" :
            self.gen_set_table()
        else :
            self.gen_get_table()
        
    def gen_set_table(self):
        #create table dir
        table_name=self.tittle + get_upper_start_str(self.name)
        
        create_dir(self.tittle +"/"+table_name)
        #print "create:" +self.tittle +"/"+table_name 

        cfile= open(self.tittle +"/"+table_name+"/"+table_name+".c", "w+")
        hfile= open(self.tittle +"/"+table_name+"/"+table_name+".h", "w+")
        index=1

        def_flag={}
        for k, v in self.json.items():
            if snmp_json.is_snmp_keyword(k)==0:
               entry=CEntryGen(self.oid, self.index, index, self.tittle, get_upper_start_str(self.name), v)
               self.enum_str+=entry.gen_enum_str();
               self.static_str+=entry.gen_static_str();
               self.oid_str+=entry.gen_oid_str();
               self.reg_str+=entry.gen_reg_str();
               self.func_str+=entry.gen_func_str();
               self.h_func_str+=entry.gen_h_func_str();
               self.transfer_function_str+=entry.gen_transfer_function_str()
               index+=1
               self.check_def(def_flag, v["_syntax"])
               
            
        cfile.write(self.gen_header()+"\n\n\n")
        cfile.write(self.gen_debug_print()+"\n\n\n")
        cfile.write(self.gen_define()+"\n\n\n")
        cfile.write(self.enum_str)
        cfile.write(self.static_str+"\n\n")
        if(len(self.transfer_function_str)>0):
            cfile.write("/*\n"+self.transfer_function_str+"\n*/\n")

        cfile.write(self.gen_init()+"\n\n")
        cfile.write(self.func_str)
        
        hfile.write(self.gen_h_def(self.gen_h_init()+self.h_func_str))
        #hfile.write(self.gen_h_init())
        #hfile.write(self.h_func_str)
        
        cfile.close()
        hfile.close()
        
    def gen_get_table(self):
        #create table dir
        table_name=self.tittle + get_upper_start_str(self.name)+"Table"
        
        create_dir(self.tittle +"/"+table_name)
        cfile= open(self.tittle +"/"+table_name+"/"+table_name+".c", "w+")
        hfile= open(self.tittle +"/"+table_name+"/"+table_name+".h", "w+")
        c_access_file= open(self.tittle +"/"+table_name+"/"+table_name+"_access.c", "w+")
        h_access_file= open(self.tittle +"/"+table_name+"/"+table_name+"_access.h", "w+")
        index=1
        first=""
        last=""
        def_flag={}
        for k, v in self.json.items():
            if not snmp_json.is_snmp_keyword(k):
               entry=CEntryGen(self.oid, self.index, index, self.tittle, get_upper_start_str(self.name), v, "get")
               self.enum_str+=entry.gen_enum_str();
               self.column_enum_str+=entry.gen_column_enum_str()
               self.column_obj_str+=entry.gen_column_obj_str()
               #self.static_str+=entry.gen_static_str();
               self.oid_str+=entry.gen_oid_str();
               self.reg_str+=entry.gen_reg_str();
               self.func_str+=entry.gen_func_str();
               self.h_func_str+=entry.gen_h_func_str();
               self.h_access_func_str+=entry.gen_get_access_func_def()
               self.c_access_func_str+=entry.gen_get_access_func(self.addtion_access)
               self.row_struct_member+=entry.gen_row_memeber()
               self.row_memeber_default_str+=entry.gen_row_memeber_default()
               self.transfer_function_str+=entry.gen_transfer_function_str()
               
               #print self.json["_get_table_index"]
               if k not in self.json["_get_table_index"] :
                   last=k
                   if len(first)==0 :
                       first=k
               
               self.check_def(def_flag, v["_syntax"])
               
               index+=1
               
               
        cfile.write(self.gen_header()+"\n\n\n")
        cfile.write(self.gen_column_enum_str(self.column_enum_str)+"\n")
        cfile.write(self.gen_column_obj_arr_str(self.column_obj_str)+"\n\n")
        cfile.write(self.gen_get_init_func()+"\n")
        cfile.write(self.gen_get_initialize_func(first, last)+"\n")
        cfile.write(self.gen_get_handler_func()+"\n")

        hfile.write(self.gen_get_h_file()+"\n")
        
        
        c_access_file.write(self.gen_access_header()+"\n\n\n")
        c_access_file.write(self.gen_debug_print()+"\n\n\n")
        c_access_file.write(self.gen_define(def_flag)+"\n\n\n")
        c_access_file.write(self.enum_str)
        c_access_file.write(self.gen_row_struct(self.row_struct_member)+"\n\n")
        if(len(self.transfer_function_str)>0):
            c_access_file.write("/*\n"+self.transfer_function_str+"\n*/\n")

        if len(self.addtion_func) > 0 :
            c_access_file.write(self.addtion_func+"\n")

        c_access_file.write(self.gen_set_row_default(self.row_memeber_default_str)+"\n")
        c_access_file.write(self.gen_find_row()+"\n")
        c_access_file.write(self.gen_find_next_row()+"\n")
        c_access_file.write(self.gen_check_ret()+"\n")
        c_access_file.write(self.c_access_func_str)
        
        h_access_file.write(self.gen_get_h_access_file(self.h_access_func_str)+"\n")
        
        
        cfile.close()
        hfile.close()
        c_access_file.close()
        h_access_file.close()
        
    def gen_header(self):
        header="""
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/snmp_handle.h>
#include "loopos/autoconfig.h"
#include "ctrl/controller/config.h"\n"""
        header+='#include "'+self.table_name+'.h"\n'
        
        if( self.is_get() ):
            header+='#include "'+self.table_name+'_access.h"\n'
            #header+='#include <net-snmp/snmp_handle.h>\n'
            
        header+= self.extra_header
            
        return header
        
    def gen_init(self):
        init="void\n"
        init+="init_"+self.tittle + get_upper_start_str(self.name)+"(void)\n"
        init+="{\n"
        init+=self.oid_str +"\n\n"
        init+=self.reg_str +""
        init+="}\n"
        return init
        
    def gen_h_init(self):
        init="void " + self.tittle + get_upper_start_str(self.name)+"(void);\n\n\n"
        return init
        
    def gen_h_def(self, context):
        h_str=self.tittle.upper()+self.name.upper()+"_H"
        h_def= "#ifndef "+ h_str +"\n"
        h_def+="#define "+ h_str +"\n\n\n\n"
        h_def+=context
        h_def+="\n#endif  /* "+   h_str + " */\n"
        return h_def
     
    def gen_column_enum_str(self, column):
        column_str="typedef enum {\n"
        column_str+=column
        column_def=self.column_def
        #index=1
        #for k, v in self.json.items():
        #    if snmp_json.is_snmp_keyword(k)==0:
        #        column_str+="    "+ column_def+"_"+k.upper()+"="+str(index)+",\n"
        #        index+=1
        #    
        column_str+="}"+column_def+";\n\n"
                
        return column_str
        
    def gen_column_obj_arr_str(self, content):
        column_str="""
static
OS_STR_SNMP_COLUMN_ENTRY my_snmp_column_obj[]=
{
"""
        column_str+=content
        column_str+="};\n"
        return column_str
        
    def gen_get_init_func(self):
        init ="/** Initializes the Table module */\n"
        init+="void\n"
        init+="init_"+self.table_name+"(void)\n"
        init+="{"
        init+="""
     /*
     * here we initialize all the tables we're planning on supporting 
     */
"""
        init+="    initialize_table_"+self.table_name+"();\n"
        init+="}\n"
        return init
        
    def gen_get_initialize_func(self, min_column, max_column):
        #to do index type ASN_OCTET_STR , mutiple index, if index remove from columobj
        index_type=""
        index_string="";
        
        for k, v in self.json.items():
            if k in self.json["_get_table_index"] :
                #print k 
                #print snmp_json.get_syntax_snmpc_type(v["_syntax"])
                index_string += get_syntax_snmpc_type(v["_syntax"])+", "

        init = "/** Initialize the table by defining its contents and how it's structured */\n"
        init+="void\n"
        init+="initialize_table_"+self.table_name+"(void)\n"
        init+="{\n"
        init+="    const oid       "+self.table_name+"_oid[] =\n"
        init+="        { 1, 3, 6, 1, 4, 1, 823, 0, "+str(self.oid)+", "+str(self.index)+" };\n"
        init+="""    netsnmp_handler_registration *reg;
    netsnmp_table_registration_info *table_info;

    reg =
        netsnmp_create_handler_registration("""
        init+='"'+self.table_name+'",\n'
        init+="                                            "+self.table_name+"_handler,\n"
        init+="                                            "+self.table_name+"_oid,\n"
        init+="                                            OID_LENGTH("+self.table_name+"_oid),\n"
        init+="                                            HANDLER_CAN_RWRITE);\n\n"
        init+="    table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);\n"
        init+="    netsnmp_table_helper_add_indexes(table_info, "+ index_string+"0);\n"
        init+="    table_info->min_column = "+self.column_def+"_"+(min_column).upper()+";\n"
        init+="    table_info->max_column = "+self.column_def+"_"+(max_column).upper()+";\n"
        init+="    netsnmp_register_table(reg, table_info);\n"
        init+="}\n"
        
        return init
        
    def gen_get_handler_func(self):
        handler = "/** handles requests for the table */\n"
        handler+="int\n"
        handler+=self.table_name+"""_handler(netsnmp_mib_handler *handler,
                       netsnmp_handler_registration *reginfo,
                       netsnmp_agent_request_info *reqinfo,
                       netsnmp_request_info *requests)
{
	return(osSnmpTable_handle_new(handler, reginfo, reqinfo, requests, my_snmp_column_obj, sizeof(my_snmp_column_obj)/sizeof(my_snmp_column_obj[0])));		
}
"""
        
        return handler
        
    def gen_get_h_file(self) :
        product_mib_list={"slotcard", "bert"}
        h_str =self.tittle.upper()+self.name.upper()+"_H"
        h_def= "#ifndef "+ h_str +"\n"
        h_def+="#define "+ h_str +"\n\n\n\n"

        """
        if self.tittle in product_mib_list:
            h_def+="config_require(mib_code/product/"+self.tittle+"/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        #elif self.tittle=="xconnect" or self.tittle=="erps":
        #    h_def+="config_require(independent/loopos_product_mib/"+self.tittle+"/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        elif self.tittle=="pwRed":
            h_def+="config_require(independent/loopos_product_mib/pseudowireRedundancy/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        elif "HOSTS" in self.tittle :
            h_def+="config_require(independent/loopos_product_mib/sdhSonetGroup/sdhHOSTSPath/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        elif "LOVT" in self.tittle:
            h_def+="config_require(independent/loopos_product_mib/sdhSonetGroup/sdhLOVTPath/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        else :
            h_def+="config_require(independent/loopos_product_mib/"+self.tittle+"/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        """

        if self.tittle=="dsx3":
            h_def+="config_require(loopos/DS3/"+self.table_name+"/"+self.table_name+"_access)\n\n"
        if self.tittle=="ds3CepPort":
            h_def+="config_require(product/"+self.tittle+"/"+self.table_name+"/"+self.table_name+"_access)\n\n"


        h_def+="void init_"+self.table_name+"(void);\n"
        h_def+="void initialize_table_"+self.table_name+"(void);\n"
        h_def+="Netsnmp_Node_Handler "+self.table_name+"_handler;\n\n"

        h_def+="\n#endif  /* "+   h_str + " */\n"        
        
        return h_def
        
    def gen_access_header(self):
        header="""
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "loopos/autoconfig.h"
"""
        header+='#include "'+self.table_name+'.h"\n'
        header+='#include "'+self.table_name+'_access.h"\n'
        
            
        header+= self.extra_header
            
        return header
        
    def gen_debug_print(self):
        debug_print="""#define BRYANT_DEBUG(fmt, args...) \\
    if(1) {                        \\
        fprintf(stderr, "\\r\\n[%d]%s %s "fmt, getpid(), __FILE__, __FUNCTION__, ##args); \\
        fprintf(stderr, "\\r\\n"); \\
    }
    """
        return debug_print

    def check_def(self, def_flag, syntax):
        if syntax == "Counter64" :
            def_flag["Counter64"]=1
        elif syntax == "AUG1STS3Index" or syntax == "VC3STS1Index" or syntax == "VC1xVTxIndex":
            def_flag["sdh_index"]=1

    def gen_define(self, def_flag={}):
        def_str=""
        if(def_flag.get("sdh_index")==1):
            def_str+="#define NOT_AVAILABLE_SDH_INDEX (255)\n"
        elif(def_flag.get("Counter64")==1):
            def_str+="#define ASSIGN64(big_split_no, big_no) big_split_no.high ="
            def_str+="((u_long *)&big_no)[1]; big_split_no.low = ((u_long *)&big_no)[0];\n"
            def_str+="static const u64 U64_ZERO=0;\n"

        return def_str
        
    def gen_row_struct(self, members):
        row_struct ="struct "+self.table_name+"_entry{\n"
        row_struct+=members
        row_struct+="};\n\n"
        row_struct+="static struct "+self.table_name+"_entry row_entry;\n"
        return row_struct
        
    def gen_get_h_access_file(self, content="") :
        h_str =self.tittle.upper()+self.name.upper()+"_ACCESS_H"
        h_def= "#ifndef "+ h_str +"\n"
        h_def+="#define "+ h_str +"\n\n\n\n"
        h_def+="int "+self.table_name+"_find_row(netsnmp_variable_list *index, void **context);\n"
        h_def+="int "+self.table_name+"_find_next_row(netsnmp_variable_list *index, void **context);\n\n\n"
        
        h_def+=content+"\n"
        
        h_def+="int check_"+self.table_name+"_ret_no_err(void *data_context, long *val,  size_t ret_len);\n"

        h_def+="\n#endif  /* "+   h_str + " */\n"        
        
        return h_def
        
    def gen_set_row_default(self, member_default):
        set_row_default ="static void \n"
        set_row_default+="set_row_default(struct "+ self.table_name +"_entry *row)\n"
        set_row_default+="{\n";
        set_row_default+=member_default;

        set_row_default+="\n}\n"
        
        return set_row_default
        
    def gen_find_row(self):
        find_row ="int \n"
        find_row+=self.table_name+"_find_row(netsnmp_variable_list *index, void **context)\n"
        find_row+="{\n";
        find_row+="    struct " + self.table_name + "_entry *row = &row_entry;\n"
        find_row+="    int ret = 0 ;\n"
        find_row+="    *context = NULL;\n"
        find_row+="    /*other def here*/\n\n"
        find_row+="    if(index==NULL)\n"
        find_row+="        return (0);\n\n"
        find_row+="    if(*index->val.integer>=10)\n"
        find_row+="        return (0);\n\n"
        find_row+="    set_row_default(row);\n\n"
        find_row+="    /*real get row here*/\n"
        find_row+="    *context = row;\n"

        find_row+="    return 1;\n}\n"
        
        return find_row
        
    def gen_find_next_row(self):
        move_to_next="""static int 
move_to_next(netsnmp_variable_list *index, void **context)
{
    // single index sample
    unsigned int index_val;
    /*other def*/
    
    if(index==NULL){
    	return (0);
    }
    
    index_val=*index->val.integer;
    
    /*real move*/
    *index->val.integer += 1;/*index val*/
    
    return 1; 
}\n
"""
    
        find_row ="int \n"
        find_row+=self.table_name+"_find_next_row(netsnmp_variable_list *index, void **context)\n"
        find_row+="{\n";
        find_row+="""    int ret = 0;
    *context = NULL;

    ret = move_to_next(index, context);

    if(ret != 1)
        return ret;\n
"""
        find_row+="    ret = "+self.table_name+"_find_row(index, context);\n"
        find_row+="    return (ret);\n}\n"
        
        return move_to_next+find_row
        
    def gen_check_ret(self):
        check="int \n"+ "check_"+self.table_name+"_ret_no_err(void *data_context, long *val,  size_t ret_len)\n"
        check+="""{
    return SNMP_ERR_NOERROR;
}
"""
        return check;
        
    def is_get(self):
        if(self.json["_type"] == "get") :
            return 1
        
        return 0
        
    def get_table_anme(self):
        return self.table_name 
        
        
        
        
        
        
        
        
        
        

class CFileGen():
    def __init__(self, json):
        self.json = json
        self.name=self.json["_name"]
        
        if len(self.name)==0: 
            print "can not find name in " +str(json)
            return
            
        if len(self.json["_short_name"])==0: 
            self.short_name = self.name
        else :
            self.short_name=json["_short_name"]
            
        self.oid=self.json["_oid"]
        self.shift_index=self.json["_shift_index"]

            
    def gen(self, src_path="", proj_name="", dst_folder=""):
        #gen root Directory
        create_dir(self.name)
        create_dir(self.short_name)
        
        
        table_dir=[]
        #gen_table
        index=self.shift_index
        for k, v in self.json.items():
            if snmp_json.is_snmp_keyword(k)==0:
                ctable=CTableGen(self.oid, index, self.short_name, k, v)
                table_dir.append(ctable.get_table_anme())
                index+=1

        if len(src_path) > 1 and len(proj_name)>0:
            dst_path="/home/bryant/Documents/git/"+proj_name
            if os.path.isdir(dst_path):
                snmp_folder_path="loopos"
                dst_path+="/loopos/snmp/"+snmp_folder_path

                if len(dst_folder)==0 :
                    dst_folder=self.name

                dst_path+="/"+dst_folder

                if os.path.isdir(dst_path):
                    delete_file(dst_path)

                cmd = "cp -R " + src_path +" " + dst_path
                print cmd
                #os.system("cp -R " + src_path +" " + dst_path)
                os.system(cmd)

                for f in table_dir:
                    print 'echo "config_require('+snmp_folder_path+"/"+dst_folder+"/"+f+"/"+f+')" >> $MIBGROUP_PATH/snmp_module.h'

            else :
                print dst_path + " not exist!"
        elif len(src_path)>0 and len(proj_name)==0:
            print "proj_name not set!"
        elif len(src_path)>0 and not os.path.isdir(dst_path):
            print dst_path + "not exist!"
        else :
            print "?????"

        
    def gen_table(self, tableName, tableContent, index):
        create_dir(self.name +"/"+self.name +tableName)
        
        """
        name=self.short_name+tableName[0].upper()+tableName[1:]
        f.write("    "+name+" OBJECT IDENTIFIER ::= { "+self.name+" "+str(index)+" }\n\n")
        
        index=1
        for k, v in tableContent.items():
            #print str(index)+"tableContent"+str(tableContent)+"!!"
            if not k.startswith("_") :
                entry=MibEntryGen(name, index, v)
                f.write(str(entry))
            index+=1 """
            
    """
        list1 = ["name", "short_name", "oid"]
        for key in list1:
            if k == key :
                return 1
        return 0
    """
    
    
    
    
    
    
        
def create_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)

def get_upper_start_str(ori_str):
    #print "get_upper_start_str:" + ori_str
    return ori_str[0].upper()+ori_str[1:]
    