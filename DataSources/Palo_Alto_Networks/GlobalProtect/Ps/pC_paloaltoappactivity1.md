#### Parser Content
```Java
{
Name = paloalto-app-activity-1
 DataType = "app-activity"
 Conditions = [ """PanOSEventIDValue=gateway-hip-report""", """GLOBALPROTECT""", ]

paloalto-vpn-event = {
    Vendor = Palo Alto Networks
    Product = GlobalProtect
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
    Fields = [
      """"receiveTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d)""",
      """PanOSSourceUserName =({user}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSPrivateIPv(4|6)=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """PanOSPublicIPv(4|6)=({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """PanOSDeviceName =({host}[\w\-.]{1,2000})""",
      """PanOSDescription=({additional_info}[^=]{1,2000})\s\w{1,100}=""",
      """PanOSEventStatus=({outcome}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSEventIDValue=({event_name}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSEndpointDeviceName =({src_host}[\w\-.]{1,2000})""",
      """PanOSEndpointOSVersion=({os}[^=]{1,2000}?)\s\d""",
      """PanOSSourceRegion=({src_country}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSAuthMethod=({auth_method}[^=]{1,2000}?)\s\w{1,100}=""",
      """({app}GLOBALPROTECT)"""
    
}
```