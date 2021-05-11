#### Parser Content
```Java
{
Name = oracle-access-manager
  Vendor = Oracle
  Product = Oracle Access Manager
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "dd/MM/yyyy HH:mm:ss Z"
  Conditions = [ """|Oracle|""", """CEF:""", """|Access Manager|""" ]
  Fields = [
    """cs5=({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\-\d{4})""",
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """dhost=({dest_host}.+?)\s{0,100}"{0,20}(\w+=|$)""",
    """dst=({dest_ip}[\da-fA-F.:]+)\s{0,100}"{0,20}(\w+=|$)""",
    """shost=({src_host}.+?)\s{0,100}"{0,20}(\w+=|$)""",
    """\ssrc=({src_ip}[\da-fA-F.:]+)\s{0,100}"{0,20}(\w+=|$)""",
    """duser=(uid\\=)+({user}[^,]+)""",
    """({app}Access Manager)""",
    """requestUrlFileName=({file_path}({file_parent}[^\s]+?)[\/]({file_name}[^\/\s]+?))\s{0,100}"{0,20}(\w+=|$)""",
    """CEF[^|]+\|([^|]*\|){4}({event_name}.+?)\s{0,100}\|""",
    """eventId=({event_code}\d{1,100})\s{0,100}"{0,20}(\w+=|$)""",
    """destinationServiceName=({service}.+?)\s{0,100}"{0,20}(\w+=|$)""",
  ]
}
```