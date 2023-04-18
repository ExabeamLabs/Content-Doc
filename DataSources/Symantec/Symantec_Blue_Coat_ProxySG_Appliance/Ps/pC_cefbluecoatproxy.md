#### Parser Content
```Java
{
Name = cef-bluecoat-proxy
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Blue Coat|Proxy SG|""", """requestMethod=""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}.+?)\s\w+=""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdst=({dest_ip}.+?)\s\w+=""",
    """\ssrc=({src_ip}.+?)\s\w+=""",
    """\sshost=({src_host}.+?)\s\w+=""",
    """\sdpt=({dest_port}\d{1,100})\s\w+=""",
    """\ssuser=({user}.+?)\s\w+=""",
    """\sact=({action}.+?)\s\w+=""",
    """\srequestMethod=({method}.+?)\s\w+=""",
    """\sout=({bytes_out}\d{1,100})\s\w+=""",
    """\sin=({bytes_in}.+?)\s\w+=""",
    """\srequestProtocol=(?:-|({protocol}.+?))\s\w+=""",
    """\sdhost=(?:-|({web_domain}.+?))\s\w+=""",
    """\srequest=(?:(-|)|({full_url}.+?))\s\w+=""",
    """\srequestUrlFileName =(?:(-|)|({uri_path}.+?))\s\w+=""",
    """\srequestUrlQuery=(?:-|({uri_query}.+?))\s\w+=""",
    """\srequestClientApplication=(?:-|({user_agent}.+?))\s\w+=""",
    """\scat=(?:(none)|({category}.+?)(;.+?)?)\s{1,100}\w+=""",
    """\s(cs1|fileType)=(?:-|({mime}.+?)(;.+?)?)\s\w+=""",
    """\scn1=(?:-|({result_code}.+?)(;.+?)?)\s\w+=""",
    """\|Blue Coat\|Proxy SG\|[^|]{0,2000}\|({proxy_action}[^|]{1,2000})\|""",
    """requestContext=(?:-|({referrer}[^\s]{1,2000}))""",
  ]
  DupFields = [ "user->orig_user" ]


}
```