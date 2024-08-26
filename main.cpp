#include <aws/core/Aws.h>
#include <aws/acm/ACMClient.h>
#include <aws/acm/model/GetCertificateRequest.h>
#include <aws/acm/model/GetCertificateResult.h>
#include <aws/secretsmanager/SecretsManagerClient.h>
#include <aws/secretsmanager/model/GetSecretValueRequest.h>
#include <aws/secretsmanager/model/GetSecretValueResult.h>
#include <nlohmann/json.hpp>
#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

#include <iostream>
#include <set>

typedef websocketpp::server<websocketpp::config::asio_tls> server;

using json = nlohmann::json_abi_v3_11_3::json;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

using connection_hdl = websocketpp::connection_hdl;
using context_ptr = std::shared_ptr<websocketpp::lib::asio::ssl::context>;

class WSS_Server {
public:
    WSS_Server() {
        m_server.init_asio();

        m_server.set_reuse_addr(true);

        m_server.set_tls_init_handler(bind(&WSS_Server::on_tls_init, this, ::_1));
        m_server.set_open_handler(bind(&WSS_Server::on_open, this, ::_1));
        m_server.set_close_handler(bind(&WSS_Server::on_close, this, ::_1));
        m_server.set_message_handler(bind(&WSS_Server::on_message, this, ::_1, ::_2));
    }

    void set_key(std::string key) {
        m_secretKey = key;
    }

    void set_cert(std::string cert) {
        m_certificate = cert;
    }

    void run(uint16_t port) {
        m_server.listen(port);
        m_server.start_accept();
        std::cout << "Listening on port: " << port << std::endl;
        m_server.run();
    }

private:
    context_ptr on_tls_init(connection_hdl hdl) {
        context_ptr ctx = std::make_shared<websocketpp::lib::asio::ssl::context>(
            websocketpp::lib::asio::ssl::context::tlsv12_server);

        try {
            ctx->set_options(websocketpp::lib::asio::ssl::context::default_workarounds |
                             websocketpp::lib::asio::ssl::context::no_sslv2 |
                             websocketpp::lib::asio::ssl::context::no_sslv3 |
                             boost::asio::ssl::context::no_tlsv1 |
                             boost::asio::ssl::context::no_tlsv1_1 |
                             websocketpp::lib::asio::ssl::context::single_dh_use);

            ctx->use_certificate_chain(
            boost::asio::buffer(m_certificate.data(), m_certificate.size()));

            ctx->use_private_key(
                boost::asio::buffer(m_secretKey.data(), m_secretKey.size()),
                boost::asio::ssl::context::file_format::pem);

        } catch (std::exception &e) {
            std::cout << "Error setting up SSL: " << e.what() << std::endl;
        }

        return ctx;
    }

    void on_open(connection_hdl hdl) {
        {
            std::cout << "Connection opened" << std::endl;
            m_connections.insert(hdl);
        }
    }

    void on_close(connection_hdl hdl) {
        {
            std::cout << "Connection closed" << std::endl;
            m_connections.erase(hdl);
        }
    }

    void on_message(connection_hdl hdl, server::message_ptr msg) {
        std::cout << "Received message: " << msg->get_payload() << std::endl;
        m_server.send(hdl, msg->get_payload(), msg->get_opcode());
    }

    server m_server;
    std::set<connection_hdl, std::owner_less<connection_hdl>> m_connections;
    std::string m_secretKey;
    std::string m_certificate;

};

int main() {

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    Aws::Client::ClientConfiguration clientConfig;
    clientConfig.region = Aws::Region::US_EAST_1;

    Aws::SecretsManager::SecretsManagerClient secretsManagerClient(clientConfig);

    const Aws::String secretName = "dev/emayl/ws-emayl.ai";

    // Create a GetSecretValueRequest object
    Aws::SecretsManager::Model::GetSecretValueRequest getSecretValueRequest;
    getSecretValueRequest.SetSecretId(secretName);

    // Call the GetSecretValue API
    auto getSecretValueOutcome = secretsManagerClient.GetSecretValue(getSecretValueRequest);

    if (getSecretValueOutcome.IsSuccess()) {
        // Successfully retrieved the secret

        const auto& secretValue = getSecretValueOutcome.GetResult().GetSecretString();
        auto secret = json::parse(secretValue);

        // std::cout << "Private Key:\n" << secretValue << std::endl;
        std::cout << "Private Key (json): " << secret["key"] << std::endl;

        WSS_Server server;
        server.set_key(secret["key"]);
        server.set_cert(secret["cert"]);
        server.run(9002);

    } else {
        // Failed to retrieve the secret
        std::cerr << "Error getting secret: " << getSecretValueOutcome.GetError().GetMessage() << std::endl;
    }

    Aws::ShutdownAPI(options);

    return 0;
}