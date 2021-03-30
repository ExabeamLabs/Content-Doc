#### Parser Content
```Java
{
Name = cef-radius-authentication-failed
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Failed Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
    """Reason\\=\[({failure_reason}.+?)\]""",
    
  ]
}
cef-aruba-nac-logon-1 = {
  Vendor = HP
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\w+ \d+ \d+ \d+:\d+:\d+)""",
    """dvc=({host}.+?)\s\w+=""",
    """duser=({user}.+?)\s\w+=""",
    """dmac=({dest_mac}.+?)\s\w+=""",
    """src=({src_ip}.+?)\s\w+=""",
    """destinationServiceName=({app}.+?)\s\w+=""",
    """reason=({failure_reason}.+?)(\s\w+=|\s*$)""",
    """msg=({additional_info}.+?)\s*$"""
    """cs1=({dest_ip}.+?)\s\w+=""",
    """cs4=({service}.+?)\s\w+=""",
   ]

```