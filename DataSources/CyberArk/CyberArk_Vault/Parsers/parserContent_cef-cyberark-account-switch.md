#### Parser Content
```Java
{
Name = cef-cyberark-account-switch
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "epoch"
  Conditions = [  """|Cyber-Ark|Vault|""", """act=Retrieve password""", """Safe""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d ({host}[\w\-.]{1,2000}) CEF""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\S+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdvchost=({host}\S+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=(({domain}[^\\=]{1,2000}?)(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """\sfname=([^=]{1,2000}?\-)?({account}[^\s-]{1,2000}?)(\\+(=.*?|({admin_id}[^\\\s]{1,2000})))?\s{1,100}\w+=""",
    """\sduser=([^\\=]{1,2000}\\+)?({account}[^=]{1,2000}?)\s{1,100}\w+=""",
    """cs2=(|({safe_value}[^=]{1,2000}?))\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```