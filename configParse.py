from io import TextIOBase
import re, itertools, json

"""
#COMMENTING THIS OUT AS ITS NOT THE FOCUS AT THE MOMENT
def grouping_tun(x):
    reg_exp = re.compile("tunnel-group\s\d+.\d+.\d+.\d+.\stype\sipsec-l2l")
    if reg_exp.match(x):
        grouping_tun.count+=1
    return grouping_tun.count       
grouping_tun.count = 0

def parseTunGroups():
    tun_group_dict = {}
    with open("tun_groups.txt","r") as file:
        for key,grp in itertools.groupby(file,grouping_tun):
            #print(key,list(grp))
            tunnel_group_list = list(grp)
            placeholder_list = []
            for command in tunnel_group_list:
                placeholder_list.append(command.lstrip().rstrip())
            #print(placeholder_list)
            tun_group_dict.update({tunnel_group_list[0].split(" ")[1]:placeholder_list.copy()})
            print(placeholder_list[0])
            placeholder_list.clear()
    #print(json.dumps(tun_group_dict,indent=4))
    return tun_group_dict
"""


def grouping_netobj(x):
    reg_exp =  re.compile("(object\s\w+\s\w+)|(object-group\s\w+\s\w+)")
    if reg_exp.match(x):
        grouping_netobj.count+=1
    return grouping_netobj.count 
grouping_netobj.count = 0

def parseNetObjs() -> dict:
    net_objs_dict = {}
    with open("netobj.txt") as file:
        for key,grp in itertools.groupby(file,grouping_netobj):
            #print(key,list(grp))
            net_objs_list = list(grp)
            placeholder_list = []
            for command in net_objs_list:
                placeholder_list.append(command.lstrip().rstrip())
            #print(placeholder_list[0])
            net_objs_dict.update({placeholder_list[0].split(" ")[2]:placeholder_list.copy()})
            placeholder_list.clear()
    #print(json.dumps(net_objs_dict,indent=4))
    return net_objs_dict

def organizeNetObj(net_obj: list, net_objs_dict: dict) -> None:
    net_obj_subnet_reg_exp = re.compile('\d+\.\d+\.\d+\.\d+\s\d+\.\d+\.\d+\.\d+')
    net_obj_fqdn_reg_exp = re.compile('fqdn\s(v4|v6)\s\S+')
    net_obj_host_reg_exp = re.compile('\d+\.\d+\.\d+\.\d+')
    net_obj_nested_obj_reg_exp = re.compile('group-object\s\S+')
    obj_name = net_obj[0].split(" ")[2]
    for entry in net_obj[1:]:
        if re.search(net_obj_fqdn_reg_exp,entry):
            fqdn_match_obj = re.search(net_obj_fqdn_reg_exp,entry)
            fqdn = "FQDN: " + fqdn_match_obj.group(0).split(" ")[1]
            print(fqdn)
            continue
        elif re.search(net_obj_subnet_reg_exp,entry):
            subnet_match_obj = re.search(net_obj_subnet_reg_exp,entry)
            subnet = "Subnet: " + subnet_match_obj.group(0)
            print(subnet)
            continue
        elif re.search(net_obj_host_reg_exp,entry):
            host_match_obj = re.search(net_obj_host_reg_exp,entry)
            host = "Host: " + host_match_obj.group(0)
            print(host)
            continue
        elif re.search(net_obj_nested_obj_reg_exp,entry):
            nested_obj_group_match = re.search(net_obj_nested_obj_reg_exp,entry)
            nested_net_obj_name = nested_obj_group_match.group(0).split(' ')[1]
            nested_net_obj = net_objs_dict[nested_net_obj_name]
            print(f"Recursively calling function for object-group {nested_net_obj_name}")
            organizeNetObj(nested_net_obj,net_objs_dict)
            continue

def parseNATsections(net_objs_dict) -> None:
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # This method reads the "sh_run_nat.txt" file, and parses the contents into a 2D list. 
    # 
    # This "sh_run_nat.txt" file is what is sounds like. It is text contents of a "show run nat" output from ASA
    # 
    # The method uses the itertools.groupby built in function to group the NAT statements into sections based on "!" delimiter
    #
    # It then saves each section as a list, and appends a copy of that list into the "nat_sections_list" list. If we do not
    # save a copy, then the original list containing nats in that section would be overwritten in the next loop iteration, as
    # the group list is a single object itself, and will overwrite previous data. 
    # 
    # We also strip each line of the nat config of \n, \t, etc character instances. This is needed since we are reading raw text, which
    # includes new-line characters, etc. 
    #
    # Finally, we call three methods, that each parse their respective NAT section (manual nat vs auto nat, etc), and return a list of
    # dictionary objects that have all the information needed to regex the NAT, get net obj info, etc. 
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    #OPEN OUTPUT OF SHOW RUN NAT
    with open("sh_run_nat.txt") as file:
        #THIS WILL BE THE LIST THAT HOLDS LISTS OF EACH NAT SECTION (MANUAL, AUTO, AFTER AUTO)
        nat_sections_list = []
        #THIS LOOP USES THE GROUPBY FUNCTION TO SPLIT NATS INTO EACH RESPECTIVE SECTION (THEY ARE DIVIDED BY !)
        for key,grp in itertools.groupby(file,lambda line: line.startswith("!")):
            # THE KEY IS THE !, BUT THE GROUP IS THE LIST OF NAME STATEMENTS IN BETWEEN EACH !
            if not key:
                #CONVERT GRP TO LIST AND SAVE A COPY AS NEXT LOOP ITERATION WILL OVERWRITE THE GRP OBJECT
                statements = list(grp).copy()
                #THIS INDEX VARIABLE IS USED TO HELP RSTRIP TRAILING CHARACTERS
                i = 0
                #FOR ALL NAT STATEMENTS IN THE SAVED GROUP (STATEMENTS)
                for statement in statements:
                    # RSTRIP WILL REMOVE \N \S ETC CHARACTERS. WE SAVE THAT INTO THE SAME INDEX LOCATION OF STATEMENTS
                    statements[i] = statement.rstrip()
                    #INCREMENT THE INDEX 
                    i = i + 1
                #APPEND A COPY OF STATEMENTS AS IT WILL BE OVERWRITTEN NEXT LOOP ITERATION
                nat_sections_list.append(statements.copy())
    
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Calling the natSyntaxhandler function for after-auto manual NAT statements
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    for manual_nat in nat_sections_list[0]:
        #print(manual_nat)
        natSyntaxhandler(net_objs_dict=net_objs_dict,nat_statement=manual_nat)
    

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # CALLING autoNATparse, WHICH RETURNS A LIST OF AUTO NAT OBJECT.
    # THEN WE CALL natSyntaxhandler, WHICH HELPS HANDLING THE PARAMETERS TO PASS TO THE REGEX FUNCTION parseNATstatement
    # 
    # autoNATparse: RETURNS A LIST OF AUTO NAT OBJECT
    # EACH AUTO NAT OBJ IS OF DICT TYPE
    # EACH ONE HAS THE FOLLOWING FIELDS:
    # {
    #   "object_name": "NETWORK OBJ NAME FOR WHICH NAT STATEMENT(S) EXIST IN",
    #   "object_syntax": "ORIGINAL SYNTAX ON THE NETWORK OBJ DEFINITION, I.E OBJECT NETWORK <<NAME>>",
    #   "auto_nat_statements": [
    #       "AUTO NAT STATEMENT #1",
    #       "AUTO NAT STATEMENT #2 - IF APPLICABLE"
    #       ]
    # }
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    # RETURNS A LIST OF AUTO NAT DICT OBJS THAT HAVE INFORMATION NEEDED TO PERFORM REGEX ON AUTO NATS
    auto_nat_config_list = autoNATparse(nat_sections_list)
    # CALL THE NAT SYNTAX HANDLER FOR EACH AUTO NAT OBJ IN LIST
    for auto_nat in auto_nat_config_list:
        #print(json.dumps(auto_nat,indent=4))
        natSyntaxhandler(net_objs_dict=net_objs_dict,is_auto_nat=True,auto_nat_dict=auto_nat)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # Calling the natSyntaxhandler function for after-auto manual NAT statements
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    for manual_nat_aa in nat_sections_list[2]:
        natSyntaxhandler(net_objs_dict=net_objs_dict,nat_statement=manual_nat_aa)

def autoNATparse(nat_sections_list: list) -> list:
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # THIS FUNCTION RETURNS A LIST OF AUTO NAT OBJECTS BASED ON THE AUTO NAT LIST PARSED IN PARSE NAT SECTIONS.
    # EACH AUTO NAT OBJ IS OF DICT TYPE
    # EACH ONE HAS THE FOLLOWING FIELDS:
    """ {
    "object_name": "NETWORK OBJ NAME FOR WHICH NAT STATEMENT(S) EXIST IN",
    "object_syntax": "ORIGINAL SYNTAX ON THE NETWORK OBJ DEFINITION, I.E OBJECT NETWORK <<NAME>>",
    "auto_nat_statements": [
        "AUTO NAT STATEMENT #1",
        "AUTO NAT STATEMENT #2 - IF APPLICABLE"
        ]
    }
    """
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # NEED LENGTH OF THE NAT SECTION LIST TO USE IN FOR LOOP RANGE
    list_length = len(nat_sections_list[1])
    # USED TO SAVE AUTO NAT OBJS INTO
    auto_nat_config_list = []
    #ITERATE OVER THE WHOLE LENGTH OF NAT SECTION LIST
    for i in range(list_length):
        #IF WE FIND THE KEYWORD "OBJECT" in nat_section_list[1] (which is the auto NAT section of the list)
        if "object" in nat_sections_list[1][i]:
            #SAVE THE OBJECT COMMAND SYNTAX
            obj_command = nat_sections_list[1][i]
            #SPLIT IT WITH " " DELIMITER TO GET OBJ NAME
            obj_name_split = obj_command.split(" ")
            #SAVE OBJ NAME, ITS LAST INDICE IN THE SPLIT LIST
            obj_name = obj_name_split[len(obj_name_split)-1]
            #WILL BE USED TO PLACE THE AUTO NATS ASSOCIATED WITH A NET OBJ INTO
            auto_nat_statement_list = []
            #FOR LIST ENTRIES BEGINNING ONE AFTER WHERE WE CURRENTLY ARE (WE ARE CURRENT AT THE OBJECT NETWORK COMMAND)
            for nat_state in nat_sections_list[1][i+1:]:
                #IF THE NEXT COMMAND IS NOT A NAT STATEMENT, THIS NET OBJ HAS NO AUTO NAT SO BREAK OUT OF LOOP
                if "object" in nat_state:
                    break
                #ELSE ITS A NAT STATEMENT, SO APPEND IT TO OUR LIST
                else:
                    auto_nat_statement_list.append(nat_state)
                #INCREMENT i AND CHECK THE NEXT INDICE TO ENSURE ITS A NAT STATEMENT
                i = i + 1
            #AFTER ALL NAT STATEMENTS HAVE BEEN FOUND FOR THAT OBJ, WE MAKE A DICT CONTAINING INFO
            auto_nat_parameters = {
                "object_name":obj_name,
                "object_syntax":obj_command,
                "auto_nat_statements":auto_nat_statement_list
            }
            # SAVE DICT TO LIST OF NATS
            auto_nat_config_list.append(auto_nat_parameters)
    #return list of auto nat dict objects
    return auto_nat_config_list

def natSyntaxhandler(net_objs_dict:dict,is_auto_nat : bool =False, auto_nat_dict : dict =None, nat_statement : str =None) -> None:
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # THIS METHOD HELPS WITH CALLING THE parseNATstatements FUNC WITH PROPER SYNTAX BASED ON NAT TYPE
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    if is_auto_nat and auto_nat_dict:
        for nat_statement in auto_nat_dict['auto_nat_statements']:
            #print(nat_statement)
            parseNATstatement(net_objs_dict=net_objs_dict,auto_nat_net_obj=auto_nat_dict['object_name'],nat_statement=nat_statement)
    else:
        parseNATstatement(net_objs_dict=net_objs_dict,nat_statement=nat_statement)
            
def parseNATstatement(net_objs_dict:dict,auto_nat_net_obj:str =None, nat_statement:str =None) -> None:
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # REGEX FOR DIFFERENT NAT TYPES
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    #REGEX FOR REAL TO MAPPED INTERFACE
    int_reg_exp = re.compile('\(.+,.+\)')
    #SOURCE REGULAR EXPERSSION
    source_reg_exp = re.compile('source\s(static|dynamic)\s\S+\s\S+')
    #DESTINATION REGULAR EXPRESSION
    dest_reg_exp = re.compile('destination\s(static|dynamic)\s\S+\s\S+')
    #SERVICE AUTO NAT REGULAR EXPRESSION. IF SERVICE DOES HAVE UDP/TCP DEFINED
    svc_auto_nat_reg_exp = re.compile('service\s(udp|tcp)\s\S+\s\S+')
    #SERVICE MANUAL NAT REGULAR EXPRESSION. IF SERVICE DOES NOT HAVE UDP/TCP DEFINED
    svc_man_nat_reg_exp = re.compile('service\s(?!(udp|tcp))\S+\s\S+')
    # DEST INTERFACE NAT/PAT REGULAR EXPRESSION
    int_mapped_reg_exp = re.compile('(static|dynamic)\sinterface')
    #REGEX FOR STATIC MATCHING A INT OR IP
    static_nat_match_int_ip = re.compile('(\d+\.\d+\.\d+\.\d+|interface)')

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # REGEX FOR DIFFERENT PARAMETERS SUCH AS PROXY ARP ETC
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # REGULAR EXPRESSION FOR THE NAT PARAMETER 'NO-PROXY-ARP'
    no_proxy_arp_reg_exp = re.compile('no-proxy-arp')
    # REGULAR EXPRESSION FOR THE NAT PARAMETER 'ROUTE-LOOKUP'
    route_lkup_reg_exp = re.compile('route-lookup')
    # REGULAR EXPRESSION FOR THE NAT PARAMETER 'AFTER-AUTO'
    after_auto_reg_exp = re.compile('after-auto')
    # FUTURE PARAMETERS MAY NEED TO INCLUDE 'DNS' FOR DNS REWRITES, 'IPV6' FOR IPV6 NAT, 'NET-TO-NET' FOR IPV4 --> IPV6 MAPPIGNS

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # DICTIONARY TO HOLD NAT INFO
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    nat_statement_def = {
        'real_interface':None,
        'mapped_interface':None,
        'nat_type':None,
        'real_source':None,
        'mapped_source':None,
        'real_destination':None,
        'mapped_destination':None,
        'service_type':None,
        'real_service':None,
        'mapped_service':None,
        'no-proxy-arp':False,
        'route-lookup':False,
        'after-auto':False
    }

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # REGEX CHECKS TO POPULATE NAT DEFINITION
    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    # GET REAL AND MAPPED INTERFACE
    int_regex_match_obj = re.search(int_reg_exp,nat_statement)
    int_match_str = int_regex_match_obj.group(0)
    int_breakdown = int_match_str.strip("(").strip(")").split(",")
    nat_statement_def['real_interface'] = int_breakdown[0]
    nat_statement_def['mapped_interface'] = int_breakdown[1]

    # IF IT IS AUTO NAT THE AUTO NAT OBJ WILL BE POPULATED
    if auto_nat_net_obj:
        nat_statement_def['real_source'] = net_objs_dict[auto_nat_net_obj]

    # IF THE TRAFFIC IS NATTED TO INTERFACE (AUTO NAT SPECIFIC)
    if re.search(int_mapped_reg_exp,nat_statement):
        auto_nat_int_match_obj = re.search(int_mapped_reg_exp,nat_statement)
        auto_nat_int_match_str_breakdown = auto_nat_int_match_obj.group(0).split(" ")
        nat_statement_def['nat_type'] = auto_nat_int_match_str_breakdown[0]
        nat_statement_def['mapped_source'] = auto_nat_int_match_str_breakdown[1]
    
    # THIS WILL ONLY MATCH FOR NON AUTO NAT SOURCES.
    # GET REAL AND MAPPED SOURCE
    if re.search(source_reg_exp,nat_statement):
        #GET SOURCE INFORMATION
        src_regex_match_obj = re.search(source_reg_exp,nat_statement)
        src_match_str = src_regex_match_obj.group(0)
        #SPLIT SOURCE AND GET NET OBJS
        source_breakdown = src_match_str.split(" ")
        nat_statement_def['nat_type'] = source_breakdown[1]
        
        #THE REAL/MAPPED SOURCE COULD BE ANY OR INTERFACE KEYWORD. FOR THIS REASON WE NEED TO CHECK IF THATS THE CASE
        any_real_map_source_reg_ex = re.compile('(any|interface)')
        # IF THE REAL SOURCE IS NOT ANY/INTERFACE
        if not re.search(any_real_map_source_reg_ex,source_breakdown[2]):
            #DO A NET_OBJS LOOKUP FOR REAL SOURCE
            nat_statement_def['real_source'] = net_objs_dict[source_breakdown[2]]
        else:
            # JUST PUT ANY OR INTERFACE
            nat_statement_def['real_source'] = source_breakdown[2]
        # IF THE MAPPED SOURCE IS NOT ANY/INTERFACE
        if not re.search(any_real_map_source_reg_ex,source_breakdown[3]):
            #DO A NET_OBJS LOOKUP FOR MAPPED SOURCE
            nat_statement_def['mapped_source'] = net_objs_dict[source_breakdown[3]]
        else:
            # JUST PUT ANY OR INTERFACE
            nat_statement_def['mapped_source'] = source_breakdown[3]

    # THIS WILL MATCH IF POLICY NAT.
    # GET REAL AND MAPPED DESTINATION
    if re.search(dest_reg_exp,nat_statement):
        #GET DESTINATION INFORMATION
        dst_regex_match_obj = re.search(dest_reg_exp,nat_statement)
        dst_match_str = dst_regex_match_obj.group(0)
        #SPLIT DEST AND GET NET OBJS
        dest_breakdown = dst_match_str.split(" ")
        nat_statement_def['real_destination'] = net_objs_dict[dest_breakdown[2]]
        nat_statement_def['mapped_destination'] = net_objs_dict[dest_breakdown[3]]

    # AUTO NAT SERVICE REGEX. IF SERVICE HAS UDP OR TCP KEYWORD IN IT, IT WILL MATCH THIS
    if re.search(svc_auto_nat_reg_exp,nat_statement):
        #GET SERVICE INFORMATION
        svc_regex_search_obj = re.search(svc_auto_nat_reg_exp,nat_statement)
        svc_search_list = svc_regex_search_obj.group(0).split(" ")
        nat_statement_def['service_type'] = svc_search_list[1]
        nat_statement_def['real_service'] = svc_search_list[2]
        nat_statement_def['mapped_service'] = svc_search_list[3]
    
    #IF THE SERVICE DOES NOT HAVE UDP/TCP DEFINED IT WILL EITHER REFERENCE ANY SERVICE OBJ OR A NAMED SERVICE OBJ
    if re.search(svc_man_nat_reg_exp,nat_statement):
        
        svc_man_nat_regex_search_obj = re.search(svc_reg_exp,nat_statement)
        svc_man_nat_search_list = svc_man_nat_regex_search_obj.group(0).split(" ")
        
        #Need to account for the any keyword for either real or mapped service. If it exists, we shouldn't lookup the object for real/mapped service.
        svc_any_reg_exp = re.compile('any')

        # If the real service matches any, we do not want to do a service obj lookup.
        # If it doesn't equal any, do a lookup into the net_objs_dict dictionary for the object.
        if not re.search(svc_any_reg_exp,svc_man_nat_search_list[1]):
            nat_statement_def['real_service'] = net_objs_dict[svc_man_nat_search_list[1]]
        else:
            nat_statement_def['real_service'] = svc_man_nat_search_list[1]
        
        # If the mapped service matches any, we do not want to do a service obj lookup.
        # If it doesn't equal any, do a lookup into the net_objs_dict dictionary for the object.
        if not re.search(svc_any_reg_exp,svc_man_nat_search_list[2]):
            nat_statement_def['real_service'] = net_objs_dict[svc_man_nat_search_list[2]]
        else:
            nat_statement_def['real_service'] = svc_man_nat_search_list[2]

    # If the no-proxy-arp parameter exists, set no-proxy-arp key to True in nat statement definition dict
    if re.search(no_proxy_arp_reg_exp,nat_statement):
        nat_statement_def['no-proxy-arp'] = True

    # If the route-lookup parameter exists, set route-lookup key to True in nat statement definition dict
    if re.search(route_lkup_reg_exp,nat_statement):
        nat_statement_def['route-lookup'] = True

    # If the after-auto parameter exists, set after-auto key to True in nat statement definition dict
    if re.search(after_auto_reg_exp,nat_statement):
        nat_statement_def['after-auto'] = True

    print("\n\n"+nat_statement+"\n")
    print(json.dumps(nat_statement_def,indent=4)+"\n\n")

def parseNAT(net_objs_dict: dict) -> None:
    #INTERFACE REGULAR EXPRESSION
    int_reg_exp = re.compile('\(.+,.+\)')
    #SOURCE REGULAR EXPERSSION
    source_reg_exp = re.compile('source\s(static|dynamic)\s\S+\s\S+')
    #DESTINATION REGULAR EXPRESSION
    dest_reg_exp = re.compile('destination\s(static|dynamic)\s\S+\s\S+')
    #DICTIONARY TO HOLD NAT INFO
    nat_dict = {}
    #OPENING TEXT FILE OF NATS
    with open('nats.txt','r') as file:
        #ITERATE THROUGH ALL NAT STATEMENTS
        for line in file:
            print("\n\n\n\n\n\n"+line+":\n")
            #SEARCH FOR (REAL INT, MAPPED INT) INFORMATION
            int_regex_match_obj = re.search(int_reg_exp,line)
            int_match_str = int_regex_match_obj.group(0)
            int_breakdown = int_match_str.strip("(").strip(")").split(",")
            int_real_int = int_breakdown[0]
            int_mapped_int = int_breakdown[1]
            # IF STATEMENT HAS SOURCE AND DESTINATION WE SEARCH AND RETREIVE THAT INFORMATION
            if re.search(dest_reg_exp,line) and re.search(source_reg_exp,line):
                #GET SOURCE INFORMATION
                src_regex_match_obj = re.search(source_reg_exp,line)
                src_match_str = src_regex_match_obj.group(0)
                #print(src_match_str)
                
                #SPLIT SOURCE AND GET NET OBJS
                source_breakdown = src_match_str.split(" ")
                source_real_source = net_objs_dict[source_breakdown[2]]
                source_mapped_source = net_objs_dict[source_breakdown[3]]

                #GET DESTINATION INFORMATION
                dst_regex_match_obj = re.search(dest_reg_exp,line)
                dst_match_str = dst_regex_match_obj.group(0)
                #print(dst_match_str)
                #SPLIT DEST AND GET NET OBJS
                dest_breakdown = dst_match_str.split(" ")
                dest_real_dest = net_objs_dict[dest_breakdown[2]]
                dest_mapped_dest = net_objs_dict[dest_breakdown[3]]
                

                #PRINT INFO
                print(f"When traffic ingresses on {int_real_int} interface")
                print(f"And the real source matches network object {source_breakdown[2]} with contents of")
                organizeNetObj(source_real_source,net_objs_dict)
                print(f"and the real destination matches network object {dest_breakdown[2]} with contents of")
                organizeNetObj(dest_real_dest,net_objs_dict)
                print("~~~~~~~~~~ THEN ~~~~~~~~~~~")
                print(f"Translate the real source to mapped source of network object {source_breakdown[3]} with contents of")
                organizeNetObj(source_mapped_source,net_objs_dict)
                print(f"Translate real destination to mapped destination of network object {dest_mapped_dest} with contents of")
                organizeNetObj(dest_mapped_dest,net_objs_dict)
                print(f"Then send the traffic to {int_mapped_int} interface (mapped interface)")

if __name__ == "__main__":
    #tun_group_dict = parseTunGroups()
    net_objs_dict = parseNetObjs()
    #nat_dict = parseNAT(net_objs_dict)
    parseNATsections(net_objs_dict)