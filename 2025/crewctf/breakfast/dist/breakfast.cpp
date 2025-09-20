#include <cereal/archives/json.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/string.hpp>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

struct Congee
{
    uint64_t ingredients[8];
    
    template <class Archive>
    void serialize(Archive& ar) { ar(CEREAL_NVP(ingredients)); }

    friend std::ostream& operator<<(std::ostream& os, const Congee& c) {
        for (auto i = 0; i < std::size(c.ingredients); i++)
            os << (i == 0 ? "" : " ") << c.ingredients[i];
        return os;
    }
};

struct Toast
{
    uint64_t spread;

    Toast(uint64_t spread = 0) : spread{spread} {}
    virtual void eat() { std::cout << "Mmm- crunchy!" << std::endl; }

    template <class Archive>
    void serialize(Archive& ar) { ar(CEREAL_NVP(spread)); }

    friend std::ostream& operator<<(std::ostream& os, const Toast& t) { return os << t.spread; }
};

struct Fruit
{
    std::string name;
    
    template <class Archive>
    void serialize(Archive& ar) { ar(CEREAL_NVP(name)); }
    
    friend std::ostream& operator<<(std::ostream& os, const Fruit& e) { return os << e.name;  }
};

int main(int argc, char**)
{
    std::cout << "Gonna pop to the store to buy some milk for breakfast.\n";
    std::cout << "Keep this data safe for me while I'm gone, alright?\n\n";

    std::stringstream ss;

    {
        cereal::JSONOutputArchive archive(ss, cereal::JSONOutputArchive::Options::NoIndent());
        std::shared_ptr<Congee> c = std::make_shared<Congee>();
        std::shared_ptr<Toast> t = std::make_shared<Toast>(Toast{42});
        std::shared_ptr<Fruit> f = std::make_shared<Fruit>(Fruit{"Apple"});
        archive(c, t, f);
    }
    std::string s = ss.str();
    s.erase(std::remove(s.begin(), s.end(), '\n'), s.end());
    std::cout << s << "\n\n";

    do
    {
        std::cout << "Remind me of the data again? ";
        std::string input;
        std::getline(std::cin, input);

        std::stringstream ss(input);
        cereal::JSONInputArchive archive(ss);

        std::shared_ptr<Congee> c;
        std::shared_ptr<Toast> t;
        std::shared_ptr<Fruit> f;
        archive(c, t, f);
        std::cout << "\nc: " << *c << std::endl;
        std::cout << "t: " << *t << std::endl;
        std::cout << "f: " << *f << std::endl;
        t->eat();
    } while (1);
}
