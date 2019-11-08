include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

################
# 生成链接库
################
#shared library

add_library(
  zk_convert
  SHARED
  convert/convertcgo.cpp
)


add_library(
  zk_redeem
  SHARED
  redeem/redeemcgo.cpp
)


add_library(
  zk_deposit
  SHARED
  deposit/depositcgo.cpp
)

add_library(
  zk_withdraw
  SHARED
  withdraw/withdrawcgo.cpp
)


###############################
# 生成各个gadget的所需的pk，vk
###############################

add_executable(
  convert_key

  convert/getpvk.cpp
)

target_link_libraries(
  convert_key

  snark
)

target_include_directories(
  convert_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  redeem_key

  redeem/getpvk.cpp
)

target_link_libraries(
  redeem_key

  snark
)

target_include_directories(
  redeem_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
###############################


add_executable(
  deposit_key

  deposit/getpvk.cpp
)

target_link_libraries(
  deposit_key

  snark
)

target_include_directories(
  deposit_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

###############################

add_executable(
  withdraw_key

  withdraw/getpvk.cpp
)

target_link_libraries(
  withdraw_key

  snark
)

target_include_directories(
  withdraw_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)






##########################################
# test setup, genProof and verProof
#########################################


#########################################
add_executable(
  convert

  convert/main.cpp
)

target_link_libraries(
  convert

  snark
)

target_include_directories(
  convert

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  redeem

  redeem/main.cpp
)

target_link_libraries(
  redeem

  snark
)

target_include_directories(
  redeem

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


#########################
add_executable(
  deposit

  deposit/main.cpp
)

target_link_libraries(
  deposit
  
  snark
)

target_include_directories(
  deposit

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)


#########################
add_executable(
  withdraw

  withdraw/main.cpp
)

target_link_libraries(
  withdraw
  
  snark
)

target_include_directories(
  withdraw

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)