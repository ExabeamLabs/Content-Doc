#### Parser Content
```Java
{
Name = s-kaspersky-es-alert-1
  Vendor = Kaspersky
  Product = Kaspersky Endpoint Security for Business
  Lms = Splunk
  DataType = "alert"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """CEF""","""|KasperskyLab|SecurityCenter|""","""cs3Label=ProductVersion""" ]
  Fields = [
    """Usuario:\s{0,100}({domain}[^\\]+)\\+({user}[^\s]+)""",
    """Componente:\s{0,100}({product_name}[^\\]+)""",
    """Resultado\\+Descripción:\s{0,100}({action}[^\\]+)""",
    """nObjeto:\s{0,100}({malware_url}[^\\]+)""",
    """Objeto\\+Tipo:\s{0,100}({alert_type}[^\\]+)""",
    """Objeto\\+Nombre:\s{0,100}({alert_name}[^\\]+)""",
    """Objeto\\+Adicional:\s{0,100}(\s|({additional_info}[^\\]+))""",
    """Fecha de lanzamiento de la base de datos:\s{0,100}({time}[^\\]+(a.\s{0,100}m.|p.\s{0,100}m.))""",
    """dhost=({dest_host}[^\s]+)\s{0,100}dst=""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    """cs6=({protocol}[^\s]+)""",
    """Aplicación\\+Nombre:\s{0,100}({app}[^\\]+)""",
    """cs4=({src_ip}[^\s]+)\s{0,100}cs4Label=AttackerIPv4""",
    """cs7=({src_port}[^\s]+)\s{0,100}cs7Label""",
    """cs8=({dest_ip}[^\s]+)\s{0,100}cs8Label=""",
    """cs5=({alert_name}.*?)\scs5Label="""
    """cs4=({alert_id}.*?)\scs4Label=TaskId""",
    """CEF:0\|([^\|]+\|){3}({alert_type}[^\|]+)\|({alert_name}[^\|]+)\|({alert_severity}[^\|])"""
	
    ]
}
```