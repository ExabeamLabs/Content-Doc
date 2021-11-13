#### Parser Content
```Java
{
Name = cisco-acs-auth-success-2
  Vendor = Cisco
  Product = Cisco ACS
  DataType = "authentication-successful"
  Conditions = [ """|Cisco Secure ACS|""", """|Authentication succeeded|""" ]

cef-acs-auth= {
 Vendor = Cisco ACS
 Lms = Direct
 TimeFormat = "epoch"
 Fields = [
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)"""
   """CEF[^|]{1,2000}\|({device_vendor}[^|]{1,2000})""",
   """CEF[^|]{1,2000}\|([^|]{0,2000}\|){2}({device_version}[^|]{1,2000})""",
   """CEF[^|]{1,2000}\|([^|]{0,2000}\|){4}({activity}[^|;\{\}=]{1,2000}?)\|""",
   """\ssuser=(N\/A|-|({user}.+?))\s{0,100}\w+=""",
   """\stype=({log_type}.+?)\s{0,100}\w+=""",
   """\sdpt=({dest_port}\d{1,100})""",
   """\ssrc=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
   """\sapp=({app}.+?)\s{0,100}\w+=""",
   """\sdeviceSeverity=\\*(Unknown|({alert_severity}.+?))\s{0,100}\w+=""",
   """\sdestinationServiceName =({service}.+?)\s{0,100}\w+=""",
   """\sdst=({dest_ip}.+?)\s{0,100}\w+=""",
   """\sdtz=({dtz}.+?)\s{0,100}\w+=""",
   """\scategoryOutcome=\/({outcome}[^\s]{1,2000})""",
   """\sahost=({src_host}[^\s]{1,2000})""",
   """\sdvchost=({host}[^\s]{1,2000})"""
   
}
```