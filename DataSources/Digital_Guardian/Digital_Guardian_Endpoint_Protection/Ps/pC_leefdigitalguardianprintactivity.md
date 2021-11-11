#### Parser Content
```Java
{
Name = leef-digitalguardian-print-activity
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "print-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Print|""" ]
}
leef-digitalguardian-print-activity = {
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "print-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]{1,2000}) LEEF:""",
    """accountName =(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000}?)\s{0,100}(\w+=|$)""",
    """IdentHostName =([^\\]{1,2000}\\+)?({dest_host}[\w\-.]{1,2000}?)\s{0,100}(\w+=|$)""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Application=({process_name}.+?)\s{0,100}(\w+=|$)""",
    """srcBytes=({bytes}\d{1,100})""",
    """Rule=({printer_name}.+?) Printer Usage""",
    """Printer=\\*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[\w\-.]{1,2000}))\\+({printer_name}.+?)\s{0,100}(\w+=|$)""",
    """SourceFile=({object}.+?)\s{0,100}(\w+=|$)""",
    """domain=({domain}.+?)\s{0,100}(\w+=|$)""",
    """LEEF:([^\|]{0,2000}\|){4}({event_code}[^\|]{1,2000})""",
  ]}
```