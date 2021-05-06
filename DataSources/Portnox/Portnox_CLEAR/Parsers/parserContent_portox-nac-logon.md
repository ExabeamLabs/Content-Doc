#### Parser Content
```Java
{
Name = portox-nac-logon
  DataType = "nac-logon"
  Conditions = [ """|Portnox""","""|CLEAR|""","""authentication success""","""act=Access ""","""The device was successfully authenticated""" ]
  Fields = ${PortnoxParserTemplates.portox-logon-events.Fields}[
    """duser=(({domain}[^\\=]+)\\+)?({user}[^\s,]+)""",
]
}
portox-logon-events = {
    Vendor = Portnox
    Product =  Portnox CLEAR
    Lms = Splunk
    TimeFormat = "epoch"
    Fields = [
      """start=({time}\d+)""",
      """exabeam_host=({host}[^\s]+)""",
      """CEF:([^|]*\|){4}({event_code}\d+)""",
      """CEF:([^|]*\|){5}({event_name}[^|]+)""",
      """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """cs4=(unknown|({auth_method}[^=]+?))\s\w+=""",
      """cs2=({policy}[^=]+?)\s\w+=""",
      """msg=({additional_info}[^=]+?)\s\w+=""",
    ]

```