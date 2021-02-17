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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """dhost=({dest_host}.+?)\s*"*(\w+=|$)""",
    """dst=({dest_ip}[\da-fA-F.:]+)\s*"*(\w+=|$)""",
    """shost=({src_host}.+?)\s*"*(\w+=|$)""",
    """\ssrc=({src_ip}[\da-fA-F.:]+)\s*"*(\w+=|$)""",
    """duser=(uid\\=)+({user}[^,]+)""",
    """({app}Access Manager)""",
    """requestUrlFileName=({file_path}({file_parent}[^\s]+?)[\/]({file_name}[^\/\s]+?))\s*"*(\w+=|$)""",
    """CEF[^|]+\|([^|]*\|){4}({event_name}.+?)\s*\|""",
    """eventId=({event_code}\d+)\s*"*(\w+=|$)""",
    """destinationServiceName=({service}.+?)\s*"*(\w+=|$)""",
  ]
}
```