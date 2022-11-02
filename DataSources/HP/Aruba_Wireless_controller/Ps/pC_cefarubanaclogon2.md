#### Parser Content
```Java
{
Name = cef-aruba-nac-logon-2
  Product = Aruba Wireless controller
  Conditions = [ """|Aruba Networks|ClearPass|""", """|Guest Access|""" ]

cef-aruba-nac-logon-1 = {
  Vendor = HP
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\w+ \d{1,100} \d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    """dvc=({host}.+?)\s\w+=""",
    """duser=({user}.+?)\s\w+=""",
    """dmac=({dest_mac}.+?)\s\w+=""",
    """src=({src_ip}.+?)\s\w+=""",
    """destinationServiceName =({app}.+?)\s\w+=""",
    """reason=({failure_reason}.+?)(\s\w+=|\s{0,100}$)""",
    """msg=({additional_info}.+?)\s{0,100}$"""
    """cs1=({dest_ip}.+?)\s\w+=""",
    """cs4=({service}.+?)\s\w+=""",
   ]
  DupFields = [ "dest_ip->auth_server" ]  
 },

leef-aruba-format = {
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = ArcSight
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s{1,100}LEEF:""",
    """devTime=({time}[^=]{1,2000}?)\s{1,100}\w+?=""",
    """action=(None|({activity}[^=]{1,2000}?))\s{1,100}\w+?=""",
    """src=({dest_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}\w+?="""
   
}
```