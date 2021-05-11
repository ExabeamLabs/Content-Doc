#### Parser Content
```Java
{
Name = cef-radius-authentication
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
   ]
  DupFields = [ "src_ip->dest_ip" ]
}
cef-aruba-nac-logon-1 = {
  Vendor = HP
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """dvc=({host}.+?)\s\w+=""",
    """duser=({user}.+?)\s\w+=""",
    """dmac=({dest_mac}.+?)\s\w+=""",
    """src=({src_ip}.+?)\s\w+=""",
    """destinationServiceName=({app}.+?)\s\w+=""",
    """reason=({failure_reason}.+?)(\s\w+=|\s{0,100}$)""",
    """msg=({additional_info}.+?)\s{0,100}$"""
    """cs1=({dest_ip}.+?)\s\w+=""",
    """cs4=({service}.+?)\s\w+=""",
   ]

```