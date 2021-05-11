#### Parser Content
```Java
{
Name = cef-sap-app-activity-3
  Product = SAP
  DataType = "file-download"
  Conditions = [ """CEF:""", """|SAP|Security Audit Log|""", """AUY""" ]
  Fields = ${SAPParserTemplates.cef-sap-app-activity.Fields} [
    """oldFileName=({file_name}.*?)\s\w+="""
  ]
}
cef-sap-app-activity = {
  Vendor = SAP
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\|Security Audit Log\|6.0\|({activity_id}[^\|]+)\|({activity}[^\|]+)\|({severity}[^\|]+)"""
    """cat=\/*({category}.*?)\s\w+=""",
    """categoryOutcome=\/*({outcome}.*?)\s\w+=""",
    """categoryObject=\/*({object}.*?)\s\w+=""",
    """ahost=\/*({host}.*?)\s\w+=""",
    """agt=\/*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """aid=\/*({aid}[^\\]+)""",
    """duser=({user}[^\s]+)""",
    """shost=({host}.*?)\s\w+=""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """suser=({user}[^\s]+)""",
    """filePath=({server}.*?)\s\w+=""",
    """AttackUserName=({username}.*?)\s\w+=""",
    """TargetUserName=({username}.*?)\s\w+=""",
    """DeviceCustomString=({host}.*?)\s\w+=""",
    """flexString2=({sid}.*?)\s\w+=""",
    """DeviceCustomString4=({client}.*?)\s\w+=""",
    """DeviceCustomString2=({transaction}.*?)\s\w+=""",
    """cs4=({result_code}\d{1,100})""", 
    """amac=({mac}.*?)\s\w+="""
  ]

```