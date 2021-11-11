#### Parser Content
```Java
{
Name = leef-digitalguardian-local-logon-1
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|23|""" ]
}
leef-digitalguardian-local-logon = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "local-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000}) LEEF:""",
    """accountName =(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000}?)\s{0,100}(\w+=|$)""",
    """IdentHostName =([^\\]{1,2000}\\+)?({dest_host}[\w\-.]{1,2000}?)\s{0,100}(\w+=|$)""",
    """Application=({process_name}.+?)\s{0,100}(\w+=|$)""",
    """({event_code}User Logon)""",
  ]}
```