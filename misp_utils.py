from pymisp import PyMISP, MISPEvent


def get_event_from_attributes(attributes):
    return attributes[0]["Event"]

def init_misp_cert(url, key, certpath):
    return PyMISP(url, key, certpath)

def query_misp(misp,iocs):

    results = []

    for value in iocs:
        try:
            search_result = misp.search(
                controller='attributes',
                value=value,
            )
            if len(search_result['Attribute']) !=0:
                results.append([value, get_event_from_attributes(search_result['Attribute'])])

        except Exception as e:
            print(f"Error searching for '{value}': {e}")
            results = []

    return results

