#### Parser Content
```Java
{
Name = thycotic-account-switch
  Vendor = Thycotic Secret Server
  Product = Thycotic Secret Server
  Lms = Direct
  DataType = "account-switch"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [  """|Thycotic Software|""","""|SECRET - CHECKOUT|""","""Item Name:""" ]
  Fields = [
    """\d{2}:\d{2}:\d{2} ({host}[\w\-.]{1,2000}) CEF:""",
    """\srt=({time}\d{1,100})""",
    """\srt=({time}\w+ \d{2} \d{4} \d{2}:\d{2}:\d{2})""",
    """\sdvc=({host}[^\s]{1,2000})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\ssuser=(({domain}[^\\=]{1,2000})(\\)+)?({user}.+?)\s{1,100}\w+=""",
    """\sfname=(({account_domain}[^\\=]{1,2000})(\\)+)?({account}.+?)\s{1,100}\w+=""",
    """cs3=({safe_value}.+?)\s{1,100}(\w+=|$)"""
  ]
	DupFields=["host->dest_host"]
}
```