#### Parser Content
```Java
{
Name = leef-mwg-proxy
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = QRadar
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ """LEEF:""","""|McAfee|Web Gateway|""" ]
    Fields = [
		"""\|devTime=({time}\d{1,100})""",
		"""\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\s(mwg:\s)?LEEF:""",
		"""\|usrName =(?:|({user}[^|]{1,2000}))\|""",
		"""\|src=(?:|({src_ip}[^|]{1,2000}))\|""",
		"""\|dst=(?:|({dest_ip}[^|]{1,2000}))\|""",
		"""\|httpStatus=(?:|({result_code}[^|]{1,2000}))\|""",
		"""\|Prot=(?:|({protocol}[^|]{1,2000}))\|""",
		"""\|(?:agent|usrAgent)=(?:|({user_agent}[^|]{1,2000}))\|""",
		"""\|Meth=(?:|({method}[^|]{1,2000}))\|""",
        """\|url=(-|({full_url}.+?))(\|\w+=|\"|\s{0,100}$|$)""",
		"""\|url=(?:|(\w+:\/+)?({web_domain}(?:({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\/:|]{1,2000}))[^|]{0,2000})(\||\"|\s{0,100}$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?({uri_path}\/[^?"|]{1,2000})[^|]{0,2000})(\||\"|\s{0,100}$|$)""",
		"""\|url=(?:|(\w+:\/+)?[^|\/:]{1,2000}(:\d{1,100})?[^|?]{1,2000}({uri_query}\?.+?))(\|\w+=|\"|\s{0,100}$|$)""",
		"""\|urlCategories=(?:|({category}[^,|]{1,2000}))(,|\|)""",
		"""\|(?:recv|BtS|dstBytes)=({bytes_in}\d{1,100})""",
		"""\|(?:sent|BfS|srcBytes)=({bytes_out}\d{1,100})""",
		"""\|blockReason=(?:|\s{0,100}({failure_reason}[^\s|][^|]{1,2000}?)\s{0,100})\|""",
        """\|blockReason=(?:|\s{0,100}({action}[^\s|][^|]{1,2000}?)\s{0,100})\|""",
		"""\|blockReason=(?:|[^|]{1,2000}by ({action}[^|]{1,2000}))\|""",
		"""\|mal=(?:|({malicious}[^|]{1,2000}))\|""",
		"""\|(?:mType|mime)=(?:|({mime}.+?))\s{0,100}(\||$)"""
    ]
  

}
```