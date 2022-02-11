#### Parser Content
```Java
{
Name = citrix-appfw-referer-header-1
  Conditions = [ """CEF:""", """|Citrix|NetScaler|NS""", """|APPFW|APPFW_REFERER_HEADER|""" ]

citrix-appfw-network-connection = {
    Vendor = Citrix
    Product =  Citrix AppFW
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
      """src=({src_ip}[a-fA-F\d:.]{1,2000})""",
      """geolocation=(Unknown|({location}[^=]{1,2000}?))\s{1,100}\w+=""",
      """spt=({src_port}\d{1,100})""",
      """method=({method}[^\s]{1,2000})""",
      """request=({full_url}[^\s]{1,2000})\smsg=""",
      """\smsg=\s{0,100}({additional_info}[^=]{1,2000}?)\s{1,100}\w+=""",
      """\|APPFW\|({event_name}[^\|]{1,2000})""",
      """\scs4=({category}[^=]{1,2000}?)\s\w+=""",
      """act=({action}[^$]{1,2000}?)\s{0,100}$""",
      """\scs1=({rule}[^=]{1,2000}?)\s\w+=""",
      """\scs2=({interface_in}[^=]{1,2000}?)\s\w+="""
    
}
```