#include <iostream>

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/filters.h>
#include <string>
#include <vector>

// first 3 bytes must be zeros
#define RANGE 3


using namespace boost::asio;
using ip::tcp;
using std::byte;

const static u_int16_t ENROLL_REGISTER{681};
const static u_int16_t ENROLL_SUCCESS{682};
const static u_int16_t ENROLL_FAILURE{683};

// enter your data here
const static std::string EMAIL{};
const static std::string FIRST_NAME{};
const static std::string LAST_NAME{};
const static std::string GITLAB_USERNAME{};
const static u_int16_t TEAM_NUMBER{};
const static u_int16_t PROJECT_CHOICE{};


const static std::string CRLF{"\r\n"};


std::array<byte, 8> uint64_to_byte_array(u_int64_t value) {
    std::array<byte, 8> byte_array{};
    for (size_t i = 0; i < byte_array.size(); ++i) {
        byte_array[i] = static_cast<byte>((value >> (8 * (7 - i))) & 0xFF);
    }
    return byte_array;
}


void pushback_CRLF(std::vector<byte>& msg) {
    msg.push_back((byte) '\r');
    msg.push_back((byte) '\n');
}

std::vector<byte> build_payload(const std::array<byte, 8> &challenge, const u_int64_t nonce) {
    std::vector<byte> msg{};
    msg.reserve(challenge.size());

    // challenge
    for (const auto &b: challenge) {
        msg.push_back(b);
    }

    // team number
    msg.push_back((byte) (TEAM_NUMBER >> 8));
    msg.push_back((byte) TEAM_NUMBER);

    // project choice
    msg.push_back((byte) (PROJECT_CHOICE >> 8));
    msg.push_back((byte) PROJECT_CHOICE);

    // nonce
    for (const auto &b: uint64_to_byte_array(nonce)) {
        msg.push_back(b);
    }

    // email
    for (const auto &b: EMAIL) {
        msg.push_back((byte) b);
    }
    pushback_CRLF(msg);

    // first name
    for (const auto &b: FIRST_NAME) {
        msg.push_back((byte) b);
    }
    pushback_CRLF(msg);


    // last name
    for (const auto &b: LAST_NAME) {
        msg.push_back((byte) b);
    }
    pushback_CRLF(msg);


    // last name
    for (const auto &b: GITLAB_USERNAME) {
        msg.push_back((byte) b);
    }
    pushback_CRLF(msg);

    return msg;
}

std::vector<byte> build_register_message(const std::vector<byte> &payload) {
    std::vector<byte> msg{};
    const u_int16_t size = payload.size() + 2 + 2;

    // size
    msg.push_back((byte) (size >> 8));
    msg.push_back((byte) size);

    // code
    msg.push_back((byte) (ENROLL_REGISTER >> 8));
    msg.push_back((byte) (ENROLL_REGISTER));

    // payload
    for (const auto &b: payload) {
        msg.push_back(b);
    }
    return msg;
}


std::tuple<u_int16_t, u_int16_t, std::array<byte, 8>> parse_response(const std::array<byte, 12> &init_response) {
    const u_int16_t size = (((u_int16_t) (init_response[0]) << 8)) | ((u_int16_t) init_response[1]);
    const u_int16_t code = (((u_int16_t) (init_response[2]) << 8)) | ((u_int16_t) init_response[3]);
    std::array<byte, 8> challenge{};
    std::copy(init_response.begin() + 4, init_response.begin() + 12, challenge.begin());
    return std::make_tuple(size, code, challenge);
}


std::string sha256(const std::string &input) {
    std::string digest;
    CryptoPP::SHA256 hash;

    CryptoPP::StringSource crypto_pp(input, true, new CryptoPP::HashFilter(hash, new CryptoPP::BaseN_Encoder(
            new CryptoPP::StringSink(digest))));
    return digest;
}


std::vector<std::byte> sha256(const std::vector<std::byte> &input) {
    CryptoPP::SHA256 hash;
    std::vector<std::byte> digest(CryptoPP::SHA256::DIGESTSIZE);

    CryptoPP::ArraySource as(reinterpret_cast<const unsigned char *>(input.data()), input.size(), true,
                             new CryptoPP::HashFilter(hash,
                                                      new CryptoPP::ArraySink(
                                                              reinterpret_cast<unsigned char *>(digest.data()),
                                                              digest.size())
                             )
    );

    return digest;
}

bool is_valid(std::vector<byte> hash) {
    return std::all_of(hash.begin(), hash.begin() + RANGE, [](byte b) -> bool { return static_cast<int>(b) == 0; });
}


int main() {

    io_service io_service;
    tcp::socket socket(io_service);

    io_context io_context;
    tcp::resolver resolver(io_context);
    tcp::resolver::query query("p2psec.net.in.tum.de", "");
    tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

    boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
    std::cout << "Resolved IP address: " << endpoint.address().to_string() << std::endl;


    ip::address address = ip::address::from_string(endpoint.address().to_string());
    u_short port = 13337;
    boost::system::error_code error;


    // connect to server
    socket.connect(tcp::endpoint(address, port));

    // read initial response from server
    std::array<byte, 12> init_response{};
    boost::asio::read(socket, buffer(init_response));
    const auto [size, code, challenge] {parse_response(init_response)};

    // for challenge, give me
    bool was_found{false};
    u_int64_t nonce{0};
    std::vector<byte> register_message;
    while (!was_found) {
        const auto payload{build_payload(challenge, nonce)};
        const auto hash{sha256(payload)};
        if (is_valid(hash)) {
            register_message = build_register_message(payload);
            was_found = true;
        } else {
            nonce++;
        }
    }

    // send register message
    boost::asio::write(socket, buffer(register_message), error);

    // receive size of enroll message
    std::uint16_t message_length;
    boost::asio::read(socket, boost::asio::buffer(&message_length, sizeof(message_length)));
    message_length = boost::endian::big_to_native(message_length) - sizeof(message_length);

    // receive content of enroll message
    std::vector<byte> enroll_msg_content(message_length);
    boost::asio::read(socket, boost::asio::buffer(enroll_msg_content.data(), message_length));

    // handle response
    if (error) {
        std::cout << "Receive failed: " << error.message() << std::endl;
    } else {
        const u_int16_t enroll_code =
                (((u_int16_t) (enroll_msg_content[0]) << 8)) | ((u_int16_t) enroll_msg_content[1]);
        if (enroll_code == ENROLL_SUCCESS) {
            const u_int16_t team_number =
                    (((u_int16_t) (enroll_msg_content[4]) << 8)) | ((u_int16_t) enroll_msg_content[5]);
            std::cout << "Your team number: " << team_number << std::endl;
        } else if (enroll_code == ENROLL_FAILURE) {
            std::stringstream ss;
            for (int i = 5; i < message_length; i++) {
                ss << (char) enroll_msg_content[i];
            }
            std::cout << "Error msg: " << ss.str() << std::endl;
        } else {
            throw std::runtime_error("Invalid code received " + std::to_string(enroll_code));
        }
    }


    socket.close();
    return 0;
}
