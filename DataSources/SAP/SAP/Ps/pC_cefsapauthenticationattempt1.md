#### Parser Content
```Java
{
Name = cef-sap-authentication-attempt-1
  DataType = "authentication-attempt"
  Conditions = [ """CEF:""", """|SECUDE|C-Bus|""", """|Authentication Assertion|""" ]

sap-activity = {
  Vendor = SAP
  Product = SAP
  Lms = Direct
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Fields = [
  """end=({time}\w{3,4} \d{1,2} \d{4} \d{1,2}:\d{1,2}:\d{1,2})"""
  """dvchost=({host}[^\s]{1,2000})""",
  """suser=({user}[^\s]{1,2000})"""
  """shost=(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({src_host}[\w.-]{1,2000}))\s"""
  """msg=({additional_info}[^=]{1,2000}?)\s{0,20}\w+="""
  """dvc=({dest_ip}[A-Fa-f:\d.]{1,2000})"""
  """duser=({account_name}[^\s]{1,2000})"""
  """cat=({category}[^=]{1,2000}?)\s{0,10}\w+="""
  """SECUDE\|C-Bus\|[^\|]{1,2000}\|(|({activity_id}[^\|]{1,2000}))\|(|(-|({event_name}[^\|]{1,2000})))\|""",
  
}
```