#### Parser Content
```Java
{
Name = portox-nac-failed-logon-2
  DataType = "nac-failed-logon"
  Conditions = [ """|Portnox""","""|CLEAR|""","""act=Access""","""account is not found""","""access was denied""" ]
  Fields = ${PortnoxParserTemplates.portox-logon-events.Fields}[
    """duser=(({domain}[^\\=]{1,2000})\\+)?({user}[^\s,]{1,2000})""",
]
}
portox-logon-events = {
    Vendor = Portnox
    Product =  Portnox CLEAR
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """start=({time}\d{1,100})""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """CEF:([^|]{0,2000}\|){4}({event_code}\d{1,100})""",
      """CEF:([^|]{0,2000}\|){5}({event_name}[^|]{1,2000})""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """cs4=(unknown|({auth_method}[^=]{1,2000}?))\s\w+=""",
      """cs2=({policy}[^=]{1,2000}?)\s\w+=""",
      """msg=({additional_info}[^=]{1,2000}?)\s\w+=""",
    ]

```