#### Parser Content
```Java
{
Name = leef-paloalto-app-activity-1
 DataType = "app-activity"
 Conditions = [ """LEEF:""", """|Palo Alto Networks|""", """globalprotect""", """|gateway-hip-report|""" ]

leef-paloalto-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
  Fields = [
      """devTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d)""",
      """PublicIPv(4|6)=(\s|({src_ip}[A-Fa-f\d:.]{1,2000}))""",
      """PrivateIPv(4|6)=(\s|({dest_ip}[A-Fa-f\d:.]{1,2000}))""",
      """AuthMethod=({auth_method}[^=]{1,2000}?)\s\w{1,100}=""",
      """usrName =((({user_email}({user}[^@]{1,2000})@({domain}[^.]{1,2000})\.\w{1,2000})\s)|(({=domain}[^\\]{1,2000})\\+)?({=user}[^\s]{1,2000}))""", 
      """DeviceName =({src_host}[\w\-.]{1,2000})""",
      """Description=({additional_info}[^=]{1,2000})\s\w{1,100}=""",
      """EventStatus=({outcome}[^=]{1,2000}?)\s\w{1,100}=""",
      """Palo Alto Networks\|Prisma Access\|2.1\|({event_name}[^|]{1,2000})\|""",
      """EndpointDeviceName =({host}[\w\-.]{1,2000})""",
      """EndpointOSVersion=({os}[^=]{1,2000}?)\s\d""",
      """SourceRegion=({src_country}[^=]{1,2000}?)\s\w{1,100}=""",
      """Portal=({app}GlobalProtect_External_Gateway)"""
    
}
```