#### Parser Content
```Java
{
Name = cef-pan-gp-vpn-login-1
  DataType = "vpn-login"
  Conditions = [ """CEF:""", """|Palo Alto Networks|PAN-OS|""", """|GLOBALPROTECT|""", """PanOSEventID=portal-prelogin""" ]

paloalto-globalprotect-template = {
    Vendor = Palo Alto Networks
    Product = GlobalProtect
    Lms = Direct
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Fields = [
      """\s({host}[\w\-.]{1,2000}?)\sCEF:""",
      """PanOSLogTimeStamp=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
      """PanOSSourceUserName =(({user_email}[^@=]{1,2000}@[^\.=]{1,2000}\.[^=]{1,2000})|(({domain}[^\\=]{1,2000})\\{1,20})?({user}[^=]{1,2000}?))\s\w{1,100}=""",
      """PanOSPrivateIPv(4|6)=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
      """PanOSPublicIPv(4|6)=({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """PanOSEventID=({event_name}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSEndpointDeviceName =({src_host}[\w\-.]{1,2000})""",
      """PanOSEventStatus=({outcome}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSAuthMethod=({auth_method}[^=]{1,2000}?)\s\w{1,100}=""",
      """({app}GLOBALPROTECT)""",
      """PanOSEndpointOSVersion="({os}[^"]{1,2000}?)"""",
      """PanOSSourceRegion=({src_country}[^=]{1,2000}?)\s\w{1,100}=""",
      """PanOSDescription="({additional_info}[^"]{1,2000})""""
    
}
```