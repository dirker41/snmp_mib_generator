import json
import snmp_c_file_gen
import snmp_mib_gen
import snmp_json
from collections import OrderedDict
import os




te1relayBox=snmp_json.SnmpObj("te1relayBox", 40 , "te1relayBox")

te1relayBoxGroupIndex=snmp_json.SnmpEntry("GroupIndex", 
[
	"slot1",
	"slot2",
	"slot3",
	"slot4",
	"slot5",
	"slot6",
	"slot7",
	"slot8",
	"slot9",
	"slot10",], "r", 
"The backup slot index.")

te1relayBoxGroupTable=snmp_json.SnmpTable("Group", "get", ["GroupIndex"], 
"The relaybox group table.",
"An entry in the relaybox group table.")

te1relayBoxCtrlSlotIndex=snmp_json.SnmpEntry("ControlSlot", 
[
	"slotA",
	"slotB",
	"slotC",
	"slotD",
	"slotE",
	"slotF"], "r", "The control slot card index.")

te1relayBoxProtectSlot=snmp_json.SnmpEntry("SlotInProtection", 
[
	"none",
	"pmml_slot2",
	"pmml_slot3",
	"pmml_slot4",
	"pmml_slot5",
	"pmml_slot6",
	"pmml_slot7",
	"pmml_slot8",
	"pmml_slot9",
	"pmml_slot10",], "r", "The protect slot index.")

te1relayBoxPower1Exist=snmp_json.SnmpEntry("Power1Exist", 
["exist", "notExist",], "r",
"Power1 exist or not.")

te1relayBoxPower1Status=snmp_json.SnmpEntry("Power1Status", 
["ok", "failure",], "r",
"Power1 status.")

te1relayBoxPower1Type=snmp_json.SnmpEntry("Power1Type", 
["type1",], "r",
"Power1 type.")

te1relayBoxPower2Exist=snmp_json.SnmpEntry("Power2Exist", 
["exist", "notExist",], "r",
"Power2 exist or not.")

te1relayBoxPower2Status=snmp_json.SnmpEntry("Power2Status", 
["ok", "failure",], "r",
"Power2 status.")

te1relayBoxPower2Type=snmp_json.SnmpEntry("Power2Type", 
["type1",], "r",
"Power2 type.")

te1relayBoxPriStatus=snmp_json.SnmpEntry("RbcPriStatus", 
["sync", "los", "lof",], "r",
"Primary RBC status.")

te1relayBoxSecStatus=snmp_json.SnmpEntry("RbcSecStatus", 
["sync", "los", "lof",], "r",
"Secondary RBC status.")

te1relayBoxLocation=snmp_json.SnmpEntry("Location", ["left", "right"], "r",
"Protect gruop location.")

te1relayBoxPcbVer=snmp_json.SnmpEntry("PmplPcbVer", "INTEGER", "r",
"PCB version.")

te1relayBoxCpldVer=snmp_json.SnmpEntry("PmplCpldVer", "INTEGER", "r",
"CPLD version.")



te1relayBoxGroupTable.add_entry(te1relayBoxGroupIndex)
te1relayBoxGroupTable.add_entry(te1relayBoxCtrlSlotIndex)
te1relayBoxGroupTable.add_entry(te1relayBoxProtectSlot)

te1relayBoxGroupTable.add_entry(te1relayBoxPower1Exist)
te1relayBoxGroupTable.add_entry(te1relayBoxPower1Status)
te1relayBoxGroupTable.add_entry(te1relayBoxPower1Type)
te1relayBoxGroupTable.add_entry(te1relayBoxPower2Exist)
te1relayBoxGroupTable.add_entry(te1relayBoxPower2Status)
te1relayBoxGroupTable.add_entry(te1relayBoxPower2Type)
te1relayBoxGroupTable.add_entry(te1relayBoxPriStatus)
te1relayBoxGroupTable.add_entry(te1relayBoxSecStatus)
te1relayBoxGroupTable.add_entry(te1relayBoxLocation)
te1relayBoxGroupTable.add_entry(te1relayBoxPcbVer)
te1relayBoxGroupTable.add_entry(te1relayBoxCpldVer)



te1relayBoxSlotIndex=snmp_json.SnmpEntry("SlotIndex", 
[
	"pmpl_slot1",
	"pmml_slot2",
	"pmml_slot3",
	"pmml_slot4",
	"pmml_slot5",
	"pmml_slot6",
	"pmml_slot7",
	"pmml_slot8",
	"pmml_slot9",
	"pmml_slot10",
	"telco_slot1",
	"telco_slot2",
	"telco_slot3",
	"telco_slot4",
	"telco_slot5",
	"telco_slot6",
	"telco_slot7",
	"telco_slot8",
	"telco_slot9",], "r", "The slot card index.")

te1relayBoxPlug=snmp_json.SnmpEntry("Plug", 
["plug", "empty",], "r",
"Slot is plug or not.")




te1relayBoxSlotTable=snmp_json.SnmpTable("Equipage", "get", ["GroupIndex", "SlotIndex"], 
"The slotcard plug table.",
"An entry in the slotcard plug table.")

te1relayBoxSlotTable.add_entry(te1relayBoxGroupIndex)
te1relayBoxSlotTable.add_entry(te1relayBoxSlotIndex)
te1relayBoxSlotTable.add_entry(te1relayBoxPlug)


te1relayBoxLedSlotIndex=snmp_json.SnmpEntry("Index", 
[
	"reserved",
	"pmml_slot2",
	"pmml_slot3",
	"pmml_slot4",
	"pmml_slot5",
	"pmml_slot6",
	"pmml_slot7",
	"pmml_slot8",
	"pmml_slot9",
	"pmml_slot10",
	"telco_slot1",
	"telco_slot2",
	"telco_slot3",
	"telco_slot4",
	"telco_slot5",
	"telco_slot6",
	"telco_slot7",
	"telco_slot8",
	"telco_slot9",], "r", "The slot card index.")

te1relayBoxPmplLedIndex=snmp_json.SnmpEntry("Index", ["ACT", "RBC_P", "RBC_S"], "r", 
"The led index.")

te1relayBoxPmplLedTable=snmp_json.SnmpTable("PmplLed", "get", ["GroupIndex", "Index"], 
"The PMPL status LEDs.",
"LED status entry contains a index and color of the specified LED.")

te1relayBoxLedName=snmp_json.SnmpEntry("Name", "display", "r", 
"The LED name.")

te1relayBoxLedColor=snmp_json.SnmpEntry("Color", 
[ "off", "green", "red", "amber", "blinkingGreen", "blinkingRed", "blinkingAmber"], "r", 
"The color of LED on the panel.")

te1relayBoxPmplLedTable.add_entry(te1relayBoxGroupIndex)
te1relayBoxPmplLedTable.add_entry(te1relayBoxPmplLedIndex)
te1relayBoxPmplLedTable.add_entry(te1relayBoxLedName)
te1relayBoxPmplLedTable.add_entry(te1relayBoxLedColor)

te1relayBoxPowerLedIndex=snmp_json.SnmpEntry("Index", ["POWER1", "POWER2"], "r", 
"The led index.")

te1relayBoxPowerLedTable=snmp_json.SnmpTable("PowerLed", "get", ["GroupIndex", "Index"], 
"The Power status LEDs.",
"LED status entry contains a index and color of the specified LED.")

te1relayBoxPowerLedTable.add_entry(te1relayBoxGroupIndex)
te1relayBoxPowerLedTable.add_entry(te1relayBoxPowerLedIndex)
te1relayBoxPowerLedTable.add_entry(te1relayBoxLedName)
te1relayBoxPowerLedTable.add_entry(te1relayBoxLedColor)


te1relayBoxSlotLedTable=snmp_json.SnmpTable("SlotLed", "get", ["GroupIndex", "Index"], 
"The slot status LEDs.",
"LED status entry contains a index and color of the specified LED.")

te1relayBoxSlotLedTable.add_entry(te1relayBoxGroupIndex)
te1relayBoxSlotLedTable.add_entry(te1relayBoxLedSlotIndex)
te1relayBoxSlotLedTable.add_entry(te1relayBoxLedName)
te1relayBoxSlotLedTable.add_entry(te1relayBoxLedColor)

te1relayBox.add_table(te1relayBoxGroupTable)
te1relayBox.add_table(te1relayBoxSlotTable)
te1relayBox.add_table(te1relayBoxPmplLedTable)
te1relayBox.add_table(te1relayBoxPowerLedTable)
te1relayBox.add_table(te1relayBoxSlotLedTable)

te1relayBox.show()

mib_file=snmp_mib_gen.MibFileGen(te1relayBox)
mib_file.gen()
cfile=snmp_c_file_gen.CFileGen(te1relayBox)
cfile.gen("./te1relayBox")