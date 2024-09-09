import socket
import sys
import logging
from dataclasses import dataclass

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Message:
    header: bytes = b''
    question: bytes = b''
    answer: bytes = b''
    authority: bytes = b''
    additional: bytes = b''

    def message(self):
        return self.header + self.question + self.answer + self.authority + self.additional

    def __repr__(self):
        return f"{self.header + self.question + self.answer + self.authority + self.additional}"


def main():
    logger.info("STARTING SERVER...")

    server_ip, server_port = "127.0.0.1", 2053
    udp_socket: socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((server_ip, server_port))

    try:
        while True:
            buf, source = udp_socket.recvfrom(512)
            logger.info(f"received: {buf} from: {source}")

            response: bytes = generate_response(buf)
            logger.info(f"response: {response} | response_length: {len(response)}")

            udp_socket.sendto(response, source)

    except Exception as e:
        logger.exception(f"Error receiving data: {e}")
    except KeyboardInterrupt:
        logger.exception("TERMINAL ERROR:")
    finally:
        logger.info("SERVER SHUT DOWN")


def generate_response(buf: bytes) -> bytes:
    dns_header = generate_response_header(buf)
    dns_question = generate_response_question(buf)
    dns_answer = generate_response_answer(dns_question)

    dns_message = Message(dns_header, dns_question, dns_answer)
    return dns_message.message()


def generate_response_header(buf: bytes) -> bytes:
    header_size = 96
    query_response_indicator = '1'
    authoritative_answer = '0'
    truncation = '0'
    recursion_available = '0'
    reserved = '000'
    question_count = '0' * 15 + '1'
    answer_record_count = '0' * 15 + '1'
    authority_record_count = '0' * 16
    additional_record_count = '0' * 16

    dns_header = bin(int().from_bytes(buf[:12], 'big'))[2:]
    if len(dns_header) < header_size:
        dns_header = '0' * (header_size - len(dns_header)) + dns_header

    packet_id = dns_header[:16]
    operation_code = dns_header[17:21]
    recursion_desired = dns_header[23:24]
    response_code = '0000' if operation_code == '0000' else '0100'

    dns_header = int((packet_id + query_response_indicator + operation_code + authoritative_answer
                      + truncation + recursion_desired + recursion_available + reserved
                      + response_code + question_count + answer_record_count + authority_record_count
                      + additional_record_count), 2).to_bytes(length=12, byteorder='big')

    return dns_header


def generate_response_question(buf) -> bytes:
    buf_index = 12
    for buf_index in range(12, len(buf)):
        if buf[buf_index: buf_index + 1] == b'\x00':
            break
    question_name = buf[12: buf_index + 1]
    question_type = int('0x0001', 0).to_bytes(2, 'big')
    question_class = int('0x0001', 0).to_bytes(2, 'big')

    return question_name + question_type + question_class


def generate_response_answer(dns_question: bytes) -> bytes:
    answer_ttl = int(60).to_bytes(4, 'big')
    answer_length = int(4).to_bytes(2, 'big')
    answer_data = b''.join(int(x, 0).to_bytes(1, 'big') for x in "8.8.8.8".split("."))

    return dns_question + answer_ttl + answer_length + answer_data


if __name__ == "__main__":
    main()
