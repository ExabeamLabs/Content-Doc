#### Parser Content
```Java
{
Name = zscaler-web-activity
  Vendor = Zscaler
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """<custom_condition>""" ]
  Fields = [
    """({time}\w+ \d+ \d+:\d+:\d+ \d\d\d\d)"\|"\w+"\|(|"({user_email}[^\|]+)")\|(|"({protocol}[^\|]+)")\|(|"({full_url}[^\|]+?)(:\d+)?")\|(|"({action}[^\|]+)")\|([^\|]*\|){2}(|"({bytes_in}[^\|]+)")\|(|"({bytes_out}[^\|]+)")\|([^\|]*\|){4}(|"({category}[^\|]+)")\|([^\|]*\|){4}(|"({src_ip}[^\|]+)")\|[^\|]*\|(|"({method}[^\|]+)")\|(|"({result_code}[^\|]+)")\|(|"({user_agent}[^\|]+)")\|([^\|]*\|){7}(|"({web_domain}[^\|]+)")\|(|"({mime}[^\|]+)")\|([^\|]*\|){8}(|"({failure_reason}[^\|]+)")\|""",
    """(\w+ \d+ \d+:\d+:\d+ \d\d\d\d)"\|"\w+"\|([^\|]*\|){2}"[^\|\/]+({uri_path}[^\?\|]+)(\/\?({uri_query}[^\|\?]+))?"\|""",
    """(\w+ \d+ \d+:\d+:\d+ \d\d\d\d)"\|"\w+"\|([^\|]*\|){29}"[^|]*?({top_domain}[^\|\.]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)(?::\d+)?)+)"\|""",
    """(\w+ \d+ \d+:\d+:\d+ \d\d\d\d)"\|"\w+"\|([^\|]*\|){21}"[^\|]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^\|]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```