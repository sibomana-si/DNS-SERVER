import socket
import sys
import logging

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
logger = logging.getLogger(__name__)

def main():
    logger.info("STARTING SERVER...")

    server_ip, server_port = "127.0.0.1", 2053
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((server_ip, server_port))

    dns_message = {'HEADER':'', 'QUESTION':'', 'ANSWER':'', 'AUTHORITY':'', 'ADDITIONAL':''}

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            logger.info(f"received: {buf} from: {source}")

            packet_id = bin(1234)[2:]
            query_response_indicator = '1'
            operation_code = '0000'
            authoritative_answer = '0'
            truncation = '0'
            recursion_desired = '0'
            recursion_available = '0'
            reserved = '000'
            response_code = '0000'
            question_count = '0' * 16
            answer_record_count = '0' * 16
            authority_record_count = '0' * 16
            additional_record_count = '0' * 16

            dns_message['HEADER'] = (packet_id + query_response_indicator + operation_code + authoritative_answer
                                     + truncation + recursion_desired + recursion_available + reserved
                                     + response_code + question_count + answer_record_count + authority_record_count
                                     + additional_record_count)

            logger.info(f"response: {dns_message['HEADER'].encode()} | length: {len(dns_message['HEADER'])}")

            response = dns_message['HEADER'].encode()
            udp_socket.sendto(response, source)
        except Exception as e:
            logger.exception(f"Error receiving data: {e}")
        except KeyboardInterrupt:
            logger.exception("TERMINAL ERROR:")
        finally:
            logger.info("SERVER SHUT DOWN")
            break


if __name__ == "__main__":
    main()
