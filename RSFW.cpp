#include "platform.h"
#include "AbstractSocket.h"
#include "SAL.h"
#include "debug.h"

const static char* m_verb[] = { "GET","HEAD","POST","OPTIONS","PUT","DELETE" }; // Do we want to support TRACE and CONNECT?
const static bool has_body[] = { false, false, true, false, true, false }; // Can have body? (ordered per above!)

class RSFW : AbstractSocket
{
private:
#define BUF_SIZE 8192
#define MAX_CL_DIGITS 9
    static bool valid[256];
    static int to_hex[256];
public:
    typedef enum {
        INTERNAL_ERROR = 1001,
        RSFW_OVERFLOW,
        INVALID_VERB,
        SYNTAX_ERROR,
        INVALID_HTTP_VERSION,
        CR_NO_LF,
        INVALID_CHAR_IN_HEADER_NAME,
        DOUBLE_CL_OR_TE,
        SYNTAX_ERROR_IN_CHUNK_HEADER,
        SYNTAX_ERROR_IN_CL,
        TE_NOT_PRECEDED_BY_CRLF,
        CHUNK_LENGTH_FIELD_TOO_LONG,
        CHUNK_LENGTH_FIELD_TOO_SHORT,
        NON_HEX_DIGIT_IN_TE,
        BODY_IS_NOT_ALLOWED,
        LF_WITHOUT_CR
    } err;

    static AbstractSocket* make_new(socket_t s, sockaddr_any* me, sockaddr_any* peer)
    {
        init();
        return new RSFW(s, me, peer);
    }
    RSFW(socket_t s, sockaddr_any* me, sockaddr_any* peer) :
        AbstractSocket(s, *me, *peer),
        m_content_length(0), m_pos(0), m_buf(new char[BUF_SIZE]), m_seen_first_line(false), m_seen_te(false), m_seen_cl(false), m_await_lf(false), m_no_more_headers(false), m_ignore_bytes(0), m_seen_te_terminal_crlf(false), m_te_mode(false), m_in_body(false), m_te_start(true), m_await_final(false), m_allow_body(false)
    {
        DEBUG30(sprintf(str_buf, "Hi, I'm a new RSFW (%p), with m_buf=%p\n", this, m_buf));
    }

    // We declare these here so they won't be auto-generated. But we don't define them, so linking will fail if ever the compiler tries to use them in the code!
    RSFW(const RSFW& from);
    RSFW& operator=(const RSFW& from);

    // DTOR must be virtual to allow inheritence later (if we need it)  
    virtual ~RSFW()
    {
        if (m_buf)
        {
            DEBUG30(sprintf(str_buf, "Oh, I'm a dying RSFW (%p), with m_buf=%p\n", this, m_buf));
            delete[] m_buf;
        }
    }

    void dump_data()
    {
        DEBUG0(sprintf(str_buf, "dump_data: Socket " SOCK_FORMAT ", %zu bytes: \n<<<", m_s, m_pos));
        for (unsigned int i = 0; i < m_pos; i++)
        {
            if (isprint(m_buf[i]))
            {
                DEBUG0RAW(sprintf(str_buf, "%c", m_buf[i]));
            }
            else
            {
                DEBUG0RAW(sprintf(str_buf, "\\x%02x", m_buf[i]));
            }
        }
        DEBUG0RAW(sprintf(str_buf, ">>>\n"));
    }
    static void init()
    {
        if (is_initialized)
        {
            return;
        }
        for (unsigned int i = 0; i < 256; i++)
        {
            if (((i >= 'a') && (i <= 'z')) || ((i >= 'A') && (i <= 'Z')) || ((i >= '0') && (i <= '9')) || (i == '-'))
            {
                valid[i] = true;
            }
            else
            {
                valid[i] = false;
            }

            if ((i >= 'a') && (i <= 'z'))
            {
                to_hex[i] = (i - 'a') + 10;
            }
            else if ((i >= 'A') && (i <= 'Z'))
            {
                to_hex[i] = (i - 'A') + 10;
            }
            else if ((i >= '0') && (i <= '9'))
            {
                to_hex[i] = i - '0';
            }
            else
            {
                to_hex[i] = -1;
            }
        }
        is_initialized = true;
    }

    size_t m_pos;
    char* m_buf;
    bool m_seen_first_line;
    bool m_in_body;
    bool m_seen_te;
    bool m_seen_cl;
    size_t m_content_length;
    //bool m_attack;
    //bool m_handle_by_eol;
    bool m_await_lf;
    bool m_no_more_headers;
    size_t m_ignore_bytes;
    bool m_seen_te_terminal_crlf;
    bool m_te_mode;
    bool m_te_start;
    bool m_await_final;
    bool m_allow_body;

    void set_error(err e)
    {
        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Encountered error %d, stopping the socket.\n", m_s, e));
        //SAL::closesocket_ptr(m_s);  // We mustn't use closesocket() because it's hooked (by us...) and it will delete the object (us!). 
	char response[]=
		"HTTP/1.1 400 Bad Request\r\n"
		"Connection: Close\r\n"
		"Content-Length: 12\r\n"
		"\r\n"
		"RSFW ERROR\r\n";
	send(m_s, response, (unsigned int)strlen(response),0 /* MSG_DONTWAIT */);

        //m_attack = true;
    }

    bool parse_first_line()
    {
        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Entering parse_first_line().\n", m_s));
        dump_data();
        if (m_pos < 15)  // minimum string is "GET / HTTP/1.0\r"
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in URL line: line too short (%zu).\n", m_s, m_pos));
            set_error(SYNTAX_ERROR);
            return false;
        }
        size_t end;
        if ((m_buf[m_pos - 2] == '\r') && (m_buf[m_pos - 1] == '\n'))
        {
            end = m_pos - 2;
        }
        else if (m_buf[m_pos - 1] == '\r')
        {
            end = m_pos - 1;
        }
        else
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR in URL line: data does not end with CR/CRLF.\n", m_s));
            set_error(INTERNAL_ERROR);
            return false;
        }

        // verb URL HTTP/1.[01]
        char* sp = (char*)memchr(m_buf, ' ', end);
        if (sp == NULL)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in URL line: no post-verb SP.\n", m_s));
            set_error(SYNTAX_ERROR);
            return false;
        }

        bool found_verb = false;
        // Note strict comparison - case sensitive.
        for (unsigned int i = 0; i < sizeof(m_verb) / sizeof(m_verb[0]); i++)
        {
            if (memcmp(m_verb[i], (const char*)m_buf, sp - m_buf) == 0)
            {
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In URL line, found verb %s.\n", m_s, m_verb[i]));
                found_verb = true;
                m_allow_body = has_body[i];
                break;
            }
        }
        if (!found_verb)
        {
            // Not found
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INVALID_VERB in URL line: no valid verb found.\n", m_s));
            set_error(INVALID_VERB);
            return false;
        }
        char* sp2 = (char*)memchr(sp + 1, ' ', m_buf + end - (sp + 1));
        if (sp2 == NULL)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in URL line: no post-URL SP.\n", m_s));
            set_error(SYNTAX_ERROR);
            return false;
        }

        // Check the URL part
        for (size_t i = (sp - m_buf)+1; i < sp2 - m_buf; i++)
        {
            if ((m_buf[i] == '\t') || (m_buf[i] == '\0'))
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in URL line: URL contains invalid characters (NUL/HT).\n", m_s));
                set_error(SYNTAX_ERROR);
                return false;
            }
            // Sanity check - this should not happen...
            if ((m_buf[i] == '\r') || (m_buf[i] == '\n') || (m_buf[i] == ' '))
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR in URL line: CR/LF/SP found in URL.\n", m_s));
                set_error(INTERNAL_ERROR);
                return false;
            }
        }
        if ((sp2 + 1 - m_buf + 8) != end)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INVALID_HTTP_VERSION in URL line: version string length error.\n", m_s));
            set_error(INVALID_HTTP_VERSION);
            return false;
        }

        // Check the version
        if ((memcmp(sp2 + 1, "HTTP/1.0", 8) != 0) && (memcmp(sp2 + 1, "HTTP/1.1", 8) != 0))
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INVALID_HTTP_VERSION in URL line: version string is not HTTP/1.0 or HTTP/1.1.\n", m_s));
            set_error(INVALID_HTTP_VERSION);
            return false;
        }

        // Everything's fine. Update the state, and allow to proceed. We don't need the data anymore, so flush it.
        m_seen_first_line = true;
        if (m_buf[m_pos - 1] == '\r')
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In URL line, moving to headers and setting await_lf=true.\n", m_s));
            m_await_lf = true;
        }
        else
        { // Seen CRLF.
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In URL line, moving to headers and setting await_lf=false.\n", m_s));
            m_await_lf = false;
        }
        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in URL line, all is well, resetting buffer and returning true.\n", m_s));
        m_pos = 0;
        return true; // allow data to be passed to the app. If it ends with CR and we never see LF, this will be the last data on this connection the app will receive...
    }

    bool parse_header()
    {
        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Entering parse_header().\n", m_s));
        if ((m_pos == 1) || ((m_pos == 2) && (m_buf[m_pos - 2] == '\r')))
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers, data length = %zu (end of headers).\n", m_s, m_pos));
            //this is a CR that that (when joined with LF) will terminate the header section.
            if (m_pos == 1)
            {
                m_await_lf = true;
            }
            m_pos = 0;
            m_no_more_headers = true;
            if (m_seen_te)
            {
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers, Seen TE.\n", m_s));
                if (!m_allow_body)
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": BODY_IS_NOT_ALLOWED.\n", m_s));
                    set_error(BODY_IS_NOT_ALLOWED);
                    return false;
                }
                //m_handle_by_eol = true;
                //m_seen_te_terminal_crlf = true; // so we're ready for the next chunk header.
                m_te_start = false;
                m_in_body = true;
                return true;
            }
            else if (m_seen_cl)
            {
                if ((!m_allow_body) && (m_content_length > 0))
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": BODY_IS_NOT_ALLOWED.\n", m_s));
                    set_error(BODY_IS_NOT_ALLOWED);
                    return false;
                }
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers, Seen CL, Content-Length=%zu, setting m_ignore_bytes accordingly.\n", m_s, m_content_length));
                //m_handle_by_eol = false;
                m_ignore_bytes = m_content_length;
                m_pos = 0;
                m_seen_first_line = false;
                m_in_body = false;
                m_seen_te = false;
                m_seen_cl = false;
                m_content_length = 0;
                //m_attack=false;
                //m_handle_by_eol=true;
                //m_await_lf=false;
                m_no_more_headers = false;
m_await_final = false;
return true;
            }
            else
            {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers, didn't see TL or TE, so no body here. Resetting to be ready for next request.\n", m_s));
            //No Content-Length, no Transfer-Encoding. So body size is 0. We're at the next request. Reset state.
            m_pos = 0;
            m_seen_first_line = false;
            m_in_body = false;
            m_seen_te = false;
            m_seen_cl = false;
            m_content_length = 0;
            //m_attack=false;
            //m_handle_by_eol=true;
            //m_await_lf=false;
            m_no_more_headers = false;
            m_ignore_bytes = 0;
            m_await_final = false;
            }
            return true;
        }
        size_t end;
        if ((m_buf[m_pos - 2] == '\r') && (m_buf[m_pos - 1] == '\n'))
        {
            end = m_pos - 2;
        }
        else if (m_buf[m_pos - 1] == '\r')
        {
            end = m_pos - 1;
        }
        else
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR in headers, header does not end with CR/CRLF.\n", m_s));
            set_error(INTERNAL_ERROR);
            return false;
        }
        char* colon = (char*)memchr(m_buf, ':', end);
        if (colon == NULL)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in headers, header does not contain colon.\n", m_s));
            dump_data();
            set_error(SYNTAX_ERROR);
            return false;
        }
        if (colon - m_buf + 2 > m_pos)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in headers, no data after colon.\n", m_s));
            set_error(SYNTAX_ERROR);
            return false;
        }
        if (*(colon + 1) != ' ')
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR in headers, no SP after colon.\n", m_s));
            set_error(SYNTAX_ERROR);
            return false;
        }
        for (unsigned int i = 0; i < colon - m_buf; i++)
        {
            if (!valid[m_buf[i]])
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INVALID_CHAR_IN_HEADER_NAME in headers. Offending character is 0x%02x.\n", m_s, m_buf[i]));
                set_error(INVALID_CHAR_IN_HEADER_NAME);
                return false;
            }
        }
        if (_strnicmp("Content-Length", m_buf, colon - m_buf) == 0)
        {
            if (m_seen_cl || m_seen_te)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": DOUBLE_CL_OR_TE in headers (Content-Length).\n", m_s));
                set_error(DOUBLE_CL_OR_TE);
                return false;
            }
            //m_content_length = 0;
            if (((end - (colon - m_buf + 2)) < 1) || ((end - (colon - m_buf + 2)) > MAX_CL_DIGITS))
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR_IN_CL in Content-Length header: invalid data width (%zu).\n", m_s, (end - (colon - m_buf + 2))));
                set_error(SYNTAX_ERROR_IN_CL);
                return false;
            }
            //DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in Content-Length header: width is %d (end=%d, colon=%p, m_buf=%p).\n", m_s, (end - (colon - m_buf + 2)), end, colon, m_buf));
            uint64_t content_length = 0;
            for (unsigned int i = 0; i < (end - (colon - m_buf + 2)); i++)
            {
                //DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in Content-Length header: seeing character <<<%c>>> (presently m_cl=%d)\n", m_s, *(colon + 2 + i), m_content_length));
                if (isdigit(*(colon + 2 + i)))
                {
                    //DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in Content-Length header: i=%d, m_cl=%d (BEFORE), char is 0x%02x\n", m_s, i, m_content_length, *(colon + 2 + i)));
                    content_length = 10 * content_length + (*(colon + 2 + i)) - '0';
                    //DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in Content-Length header: i=%d, m_cl=%d (AFTER), char is 0x%02x\n", m_s, i, m_content_length, *(colon + 2 + i)));
                }
                else
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR_IN_CL in Content-Length header: non-digit characher (0x%02x).\n", m_s, *(colon + 2 + i)));
                    set_error(SYNTAX_ERROR_IN_CL);
                    return false;
                }
            }
            if ((sizeof(content_length) > sizeof(m_content_length)) && (content_length >= (1ull << (8 * sizeof(m_content_length)))))
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR_IN_CL in Content-Length header: length overflow (%llu).\n", m_s, (unsigned long long int)content_length));
                set_error(SYNTAX_ERROR_IN_CL);
                return false;
            }
            m_content_length = (size_t)content_length;
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in headers, Content-Length is %zu.\n", m_s, m_content_length));
            m_seen_cl = true;
        }
        else if (_strnicmp("Transfer-Encoding", m_buf, colon - m_buf) == 0)
        {
            if (m_seen_cl || m_seen_te)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": DOUBLE_CL_OR_TE in headers (Transfer-Encoding).\n", m_s));
                set_error(DOUBLE_CL_OR_TE);
                return false;
            }
            if (((m_pos - (colon - m_buf + 2)) < 9) || strncmp(" chunked\r", colon + 1, 9) != 0)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR_IN_TE in headers: data is not 'chunked'.\n", m_s));
                set_error(SYNTAX_ERROR_IN_CHUNK_HEADER);
                return false;
            }
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in headers, saw Transfer-Encoding: chunkned.\n", m_s));
            m_seen_te = true;
        }
        // Everything's fine. Update the state, and allow to proceed. We don't need the data anymore, so flush it.
        if (m_buf[m_pos - 1] == '\r')
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers: moving to the next header and setting await_lf=true.\n", m_s));
            m_await_lf = true;
        }
        else
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In headers: moving to the next header and setting await_lf=false.\n", m_s));
            m_await_lf = false;
        }
        m_pos = 0;
        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in headers, all is well, resetting buffer and returning true.\n", m_s));
        return true; // allow data to be passed to the app. If it ends with CR and we never see LF, this will be the last data on this connection the app will receive...

    }

    bool parse_te()
    {
        if (m_pos == 0)
        {
            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR.\n", m_s));
            set_error(INTERNAL_ERROR);
            return false;
        }
        else if (m_await_final)
        {
            m_await_lf = m_buf[m_pos - 1] == '\r';
            // End of HTTP request - reset to be ready for the next request.
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in the final chunk, just go the final CR (+LF?).\n", m_s));

            m_pos = 0;
            m_seen_first_line = false;
            m_in_body = false;
            m_seen_te = false;
            m_seen_cl = false;
            m_content_length = 0;
            //m_attack=false;
            //m_handle_by_eol=true;
            //m_await_lf = false;
            m_no_more_headers = false;
            m_ignore_bytes = 0;
            m_await_final = false;
            return true;
        }
        else if (m_te_start)
        {
            if (m_buf[0] == '\r')
            {
                if (m_pos == 2)
                {
                    if (m_buf[1] == '\n')
                    {
                        m_pos = 0;
                        m_te_start = false;
                        return true;
                    }
                    else
                    {
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR in TE chunk, chunk does not end with CR/CRLF.\n", m_s));
                        set_error(INTERNAL_ERROR);
                        return false;
                    }
                }
                m_te_start = false;
                m_await_lf = true;
                m_pos = 0;
                return true;
            }
            else
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": TE_NOT_PRECEDED_BY_CRLF in TE chunk, chunk  is not preceded by CRLF.\n", m_s));
                set_error(TE_NOT_PRECEDED_BY_CRLF);
                return false;
            }
        }
        else
        {
            if (m_pos < 2)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": SYNTAX_ERROR_IN_CHUNK_HEADER in TE chunk, chunk is empty.\n", m_s));
                set_error(SYNTAX_ERROR_IN_CHUNK_HEADER);
                return false;
            }
            uint64_t eff_len = (m_buf[m_pos - 1] == '\n') ? (m_pos - 2) : (m_pos - 1);
            if (eff_len > 8)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": CHUNK_LENGTH_FIELD_TOO_LONG in TE chunk.\n", m_s));
                set_error(CHUNK_LENGTH_FIELD_TOO_LONG);
                return false;
            }
            if (eff_len < 1)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": CHUNK_LENGTH_FIELD_TOO_SHORT in TE chunk.\n", m_s));
                set_error(CHUNK_LENGTH_FIELD_TOO_SHORT);
                return false;
            }

            uint32_t len = 0;
            for (unsigned int i = 0; i < eff_len; i++)
            {
                int x = to_hex[(unsigned char)m_buf[i]];
                if (x < 0)
                {
                    dump_data();
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": NON_HEX_DIGIT_IN_TE in TE chunk.\n", m_s));
                    set_error(NON_HEX_DIGIT_IN_TE);
                    return false;
                }
                len = (len << 4) + x;
            }

            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in a chunk header, chunk length is %d.\n", m_s, len));

            if (len == 0)
            {
                m_await_lf = m_buf[m_pos - 1] == '\r';
                m_await_final = true;
                m_pos = 0;
                return true;
            }
            else
            {
                m_ignore_bytes = len;
                m_await_lf = m_buf[m_pos - 1] == '\r';
                m_te_start = true; // so the CRLF after the chunk will be gobbled!
                m_pos = 0;
            }
            return true;
        }
    }
    bool process()
    {
        //DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": in process(), data below.\n", m_s));
        //dump_data();
        if (!m_seen_first_line)
        {
            if (!parse_first_line())
            {
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": process() returning false.\n", m_s));
                return false;
            }
            else
            {
                return true;
            }
        }
        else if (!m_in_body)
        {
            if (!parse_header())
            {
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": process() returning false.\n", m_s));
                return false;
            }
            else
            {
                return true;
            }
        }
        else
        {
            // In body
            if (m_ignore_bytes > 0)
            {
                DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": INTERNAL_ERROR: process called when ingnored_bytes (%zu) > 0.\n", m_s, m_ignore_bytes));
                return false;
            }
            else if (m_seen_te)
            {
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In body, looking at a chunk header.\n", m_s));
                if (!parse_te())
                {
                    DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": process() returning false.\n", m_s));
                    return false;
                }
                else
                {
                    return true;
                }
            }
            else
            {
                // This was a Content-Length specified body, and it was entirely consumed. So we're in a new request. Reset everything...
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": In body with Content-Length, all body is consumed. Resetting to be ready for next request.\n", m_s));
                m_pos = 0;
                m_seen_first_line = false;
                m_in_body = false;
                m_seen_te = false;
                m_seen_cl = false;
                m_content_length = 0;
                //m_attack=false;
                //m_handle_by_eol=true;
                m_await_lf = false;
                m_no_more_headers = false;
                m_ignore_bytes = 0;
                return true;
            }
        }
    }

    bool onRead(char* buf, size_t len)
    {
        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Received %zu bytes.\n", m_s, len));
        //if (m_attack)
        //{
            //DEBUG10(sprintf(str_buf,"RSFW: Socket " SOCK_FORMAT ": under attack, ignoring data.\n", m_s));
            //return false;
        //}
        size_t start = 0;
        while (start < len)
        {
            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": handling bytes - m_ignore_bytes=%zu.\n", m_s, m_ignore_bytes));
            if (m_await_lf && (len > 0))
            {
                if (buf[start] == '\n')
                {
                    DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": ignoring LF.\n", m_s));
                    // Everything's already taken care of, so ignore this LF and move on...
                    start++;
                    m_await_lf = false;
                }
                else
                {
                    DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": CR_NO_LF error.\n", m_s));
                    set_error(CR_NO_LF);
                    return false;
                }
            }
            else if (m_ignore_bytes > 0)
            {
                size_t consumed = MIN(m_ignore_bytes, len - start);
                start += consumed;
                m_ignore_bytes -= consumed;
                DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": ignoring %zu bytes.\n", m_s, consumed));
            }
            else
                //if (m_handle_by_eol)
            {
                for (size_t i = start; i < len; i++)
                {
                    //if ((buf[i] == '\r') || (buf[i] == '\n'))
                    if (buf[i] == '\r')
                    {
                        // Save us the double process in case of the (very likely) CRLF sequence
                        if (((i + 1) < len) && (buf[i] == '\r') && (buf[i + 1] == '\n'))
                        {
                            DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Detected LF after CR, so adding the LF.\n", m_s));
                            i++;
                        }
                        if ((m_pos + i - start + 1) > BUF_SIZE)
                        {
                            DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": RSFW_OVERFLOW error: too much data in EOL handling mode.\n", m_s));
                            set_error(RSFW_OVERFLOW);
                            return false;
                        }
                        memcpy(m_buf + m_pos, buf + start, i - start + 1);
                        m_pos += i - start + 1;
                        DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": Calling process().\n", m_s));
                        if (process())
                        {
                            start = i + 1;
                            goto next;
                        }
                        else
                        {
                            DEBUG10(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": process() failed.\n", m_s));
                            return false;
                        }
                    }
                    else if (buf[i] == '\n')
                    {
                        // LF but not CRLF
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": LF_WITHOUT_CR.\n", m_s));
                        set_error(LF_WITHOUT_CR);
                        return false;
                    }
                }
                // Line is incomplete
                if (start < len)
                {
                    if ((m_pos + len - start) > BUF_SIZE)
                    {
                        DEBUG0(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": RSFW_OVERFLOW: remaining buffer causes overflow\n", m_s));
                        set_error(RSFW_OVERFLOW);
                        return false;
                    }
                    DEBUG20(sprintf(str_buf, "RSFW: Socket " SOCK_FORMAT ": storing the remaining buffer.\n", m_s));
                    memcpy(m_buf + m_pos, buf + start, len - start);
                    m_pos += len - start;
                    break;
                }
            }
        next:;
        }
        return true;
    }

    static bool is_initialized;
};

bool RSFW::is_initialized = false;
bool RSFW::valid[256];
int RSFW::to_hex[256];

SAL::generator SAL::gen_f = RSFW::make_new;
