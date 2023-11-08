import pandas as pd

FILE_PATH = 'service-names-port-numbers.csv'
TARGET_SERVICE = ['mysql', 'ftp', 'http', 'smtp', 'dns', 'dhcp', 'telnet', 'ssh']

def load_csv(path):
    df = pd.read_csv(path)
    return df

def replace_description(df):
    description_list = df['Description'].to_list()
    for dl in range(len(description_list)):
        for sl in TARGET_SERVICE:
            if sl in description_list[dl]:
                description_list[dl] = sl
            else:
                continue
    return description_list

def pre_process(df):
    # Port Number, Description 제외 모두 삭제
    port_des_df = df[['Port Number', 'Description']]
    
    # 결측치 제거
    port_des_df = port_des_df.dropna()
    
    # 모두 소문자 변환
    port_des_df['Description'] = port_des_df['Description'].str.lower()

    # 원하는 서비스만 필터링
    conditions = '|'.join(TARGET_SERVICE) 
    filter_df = port_des_df[port_des_df['Description'].str.contains(conditions, case=False, na=False)]
    port_list = filter_df['Port Number'].tolist()

    # SERVICE LIST 형태로 Replace
    service_list = replace_description(filter_df)
    return port_list, service_list

def main_start():
    df = load_csv(FILE_PATH)
    port, service= pre_process(df)
    create_csv(port, service)
    
def create_csv(port, service):
    df = pd.DataFrame({"port": port, "service": service})
    df.to_csv("port_service.csv", index=False)
    print("[+] CSV 변환 완료")
    
if __name__ == "__main__":
    main_start()
