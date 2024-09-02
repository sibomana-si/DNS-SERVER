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

            # Header
            packet_id = bin(1234)[2:]
            query_response_indicator = '1'
            operation_code = '0000'
            authoritative_answer = '0'
            truncation = '0'
            recursion_desired = '0'
            recursion_available = '0'
            reserved = '000'
            response_code = '0000'
            question_count = '0'*15 + '1'
            answer_record_count = '0'*15 + '1'
            authority_record_count = '0'*16
            additional_record_count = '0'*16

            # Question
            question_name = '\x0ccodecrafters\x02io\x00'.encode()
            question_type = int('0x0001', 0).to_bytes(2, 'big')
            question_class = int('0x0001', 0).to_bytes(2, 'big')

            # Answer
            answer_ttl = int(60).to_bytes(4, 'big')
            answer_length = int(4).to_bytes(2, 'big')
            answer_data = b''.join(int(x, 0).to_bytes(1, 'big') for x in "8.8.8.8".split("."))


            dns_message['HEADER'] = int((packet_id + query_response_indicator + operation_code + authoritative_answer
                                     + truncation + recursion_desired + recursion_available + reserved
                                     + response_code + question_count + answer_record_count + authority_record_count
                                     + additional_record_count), 2).to_bytes(length=12, byteorder='big')

            dns_message['QUESTION'] = (question_name + question_type + question_class)

            dns_message['ANSWER'] = (dns_message['QUESTION'] + answer_ttl + answer_length + answer_data)

            logger.info(f"response_header: {dns_message['HEADER']} | length: {len(dns_message['HEADER'])}")
            logger.info(f"response_question: {dns_message['QUESTION']} | length: {len(dns_message['QUESTION'])}")
            logger.info(f"response_answer: {dns_message['ANSWER']} | length: {len(dns_message['ANSWER'])}")

            response = (dns_message['HEADER'] + dns_message['QUESTION'] + dns_message['ANSWER'])
            print(f"response: {response} | response_length: {len(response)}")
            udp_socket.sendto(response, source)
        except Exception as e:
            logger.exception(f"Error receiving data: {e}")
            break
        except KeyboardInterrupt:
            logger.exception("TERMINAL ERROR:")
            break


if __name__ == "__main__":
    main()
